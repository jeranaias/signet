"""KeyRing — secret key management for the HMAC audit chain.

A :class:`KeyRing` holds the keys used to sign and verify audit entries.
The simplest deployment uses a single key for the chain's lifetime; richer
deployments rotate keys periodically and need to verify entries signed
under previous keys.

Key rotation produces multiple *eras*. Each era is a contiguous run of
entries signed under the same key. Entries written after a rotation use
the new key but are still chained (via ``prev_hmac``) to the last entry of
the previous era. Verification walks the whole chain, switching keys at
era boundaries.

This module is crypto-free at the interface — it just stores key bytes.
The actual HMAC computation lives in :mod:`signet.audit.chain`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Key:
    """A single signing key with an opaque identifier.

    Attributes:
        key_id: Stable identifier for this key. Conventionally a short
            string like ``"k1"``, ``"k2"``, or a date stamp like
            ``"2026-05-03"``. Embedded in audit entries so the verifier
            knows which key to use.
        secret: The HMAC secret. Treat as cleartext; this object should
            never be serialized to logs or telemetry.
    """

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("Key.key_id must be a non-empty string")
        if len(self.secret) < 16:
            raise ValueError(
                f"Key.secret must be at least 16 bytes (got {len(self.secret)}); "
                "32 bytes recommended for HMAC-SHA256"
            )

    def __repr__(self) -> str:
        # Override the default dataclass repr so the secret never lands in
        # logs, exception tracebacks, or REPL output. The length is exposed
        # because it's useful for diagnosing key-size misconfiguration and
        # does not weaken the secret.
        return f"Key(key_id={self.key_id!r}, secret=<{len(self.secret)} bytes redacted>)"

    @classmethod
    def generate(cls, key_id: str, *, length: int = 32) -> Key:
        """Generate a new key with a cryptographically-random secret.

        ``length`` defaults to 32 bytes (256 bits), matching the HMAC-SHA256
        block-internal state size — the standard recommendation.
        """
        return cls(key_id=key_id, secret=secrets.token_bytes(length))


@dataclass
class KeyRing:
    """Ordered set of keys covering one or more eras of an audit chain.

    The *active* key is the one used to sign new entries. All other keys
    in the ring are still trusted for verification of entries that were
    written under them.

    Construct with the active key. Add older keys via :meth:`add_legacy`
    when bringing an existing chain online. Rotate to a new active key
    via :meth:`rotate`.

    Constructor ergonomics: ``KeyRing(active=Key(...))`` is the
    historical signature. ``KeyRing(keys=[...], active_id="k1")`` and
    ``KeyRing(keys={"k1": Key(...), "k2": Key(...)}, active_id="k1")``
    are accepted shorthands for callers that already have a list / dict
    of keys.
    """

    _active: Key
    _legacy: dict[str, Key] = field(default_factory=dict)

    def __init__(
        self,
        active: Key | None = None,
        *,
        keys: list[Key] | dict[str, Key] | None = None,
        active_id: str | None = None,
    ) -> None:
        if active is not None:
            if keys is not None or active_id is not None:
                raise ValueError("pass either active= or (keys=, active_id=), not both")
            self._active = active
            self._legacy = {}
            return

        if keys is None:
            raise TypeError(
                "KeyRing requires active= or (keys=, active_id=) to identify the signing key"
            )
        if active_id is None:
            raise TypeError(
                "KeyRing(keys=...) requires active_id= so the signing key is unambiguous"
            )

        # Normalize list[Key] → dict[str, Key].
        if isinstance(keys, list):
            keys_by_id: dict[str, Key] = {}
            for k in keys:
                if k.key_id in keys_by_id:
                    raise ValueError(f"duplicate key_id {k.key_id!r} in keys= list")
                keys_by_id[k.key_id] = k
        else:
            keys_by_id = dict(keys)

        if active_id not in keys_by_id:
            raise ValueError(
                f"active_id {active_id!r} not present in keys= (known ids: {sorted(keys_by_id)!r})"
            )
        self._active = keys_by_id.pop(active_id)
        self._legacy = keys_by_id

    @property
    def active(self) -> Key:
        """The current signing key. New entries are signed with this key."""
        return self._active

    def get(self, key_id: str) -> Key | None:
        """Look up a key by ID. Returns ``None`` if no such key is known."""
        if key_id == self._active.key_id:
            return self._active
        return self._legacy.get(key_id)

    def add_legacy(self, key: Key) -> None:
        """Register a previous-era key for verification only.

        The added key is not used for signing. Raises :class:`ValueError`
        if a key with the same ID is already registered.
        """
        if key.key_id == self._active.key_id:
            raise ValueError(f"Cannot add legacy key with same ID as active key: {key.key_id!r}")
        if key.key_id in self._legacy:
            raise ValueError(f"Legacy key {key.key_id!r} already registered")
        self._legacy[key.key_id] = key

    def rotate(self, new_active: Key) -> None:
        """Promote ``new_active`` to the signing role; demote the previous
        active key to legacy verification-only.

        Raises :class:`ValueError` if ``new_active`` already exists in the
        ring under any role.
        """
        if new_active.key_id == self._active.key_id:
            raise ValueError(f"New active key has same ID as current active: {new_active.key_id!r}")
        if new_active.key_id in self._legacy:
            raise ValueError(f"New active key {new_active.key_id!r} already exists as legacy")
        self._legacy[self._active.key_id] = self._active
        self._active = new_active

    def all_known_ids(self) -> tuple[str, ...]:
        """All key IDs currently in the ring (active + legacy), in
        insertion order with the active key first."""
        return (self._active.key_id, *self._legacy.keys())
