"""HmacChain — the writer that signs audit entries and links them.

Each appended entry's HMAC depends on:

1. The entry's own payload (everything except the ``hmac`` field itself).
2. The HMAC of the previous entry, carried in ``prev_hmac``.

Tampering with any entry breaks its own HMAC; tampering further back
breaks every entry afterwards because the chain link no longer matches.
The verifier in :mod:`signet.audit.verifier` walks the chain and reports
exactly where a break occurs.

Concurrency: ``append`` holds an internal :class:`threading.Lock` so
single-process concurrent callers (FastAPI's async event loop counts
as one) cannot fork the chain by reading the same ``prev_hmac`` twice
before either writes. **Multi-process** writers (e.g. ``uvicorn
--workers 2``) are not protected; each worker has its own lock and
its own ``_cached_prev``. Run signet with a single worker, or plug in
a custom backend that takes a cross-process lock (e.g. ``fcntl.flock``
on POSIX, ``msvcrt.locking`` on Windows). Multi-process safe writers
are tracked for v0.2.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import replace
from typing import Any

from signet.audit.backend import AuditBackend
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry

#: Field name embedded in entry metadata to identify the signing key.
#: Verification reads this to look up the right key in the :class:`KeyRing`.
KEY_ID_FIELD = "_signing_key_id"


class HmacChain:
    """Append-and-sign coordinator over a backend and key ring.

    Construct with a :class:`signet.audit.backend.AuditBackend` and a
    :class:`signet.audit.keyring.KeyRing`. Call :meth:`append` for each
    new entry; the chain takes care of computing ``prev_hmac``, signing,
    and persisting through the backend.

    The signing-key ID is stamped into the entry's metadata under
    :data:`KEY_ID_FIELD` so the chain remains verifiable across key
    rotations without out-of-band coordination.
    """

    def __init__(self, backend: AuditBackend, keyring: KeyRing) -> None:
        self._backend = backend
        self._keyring = keyring
        # Cache the last entry's HMAC so we don't have to scan the
        # backend on every append. A None sentinel means "haven't loaded
        # yet"; an empty string means "chain is genuinely empty".
        self._cached_prev: str | None = None
        # Serialize concurrent appends. Required because two coroutines
        # racing through read_prev → compute → write would otherwise both
        # see the same prev_hmac and fork the chain. See module docstring
        # for the multi-process caveat.
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Sign and persist ``entry``; return the linked entry.

        The returned entry has ``prev_hmac``, ``hmac``, and the signing
        key ID populated. The original ``entry`` argument is unchanged
        (entries are frozen).
        """
        with self._lock:
            prev_hmac = self._read_prev_hmac()
            active = self._keyring.active

            # Embed the signing key ID so the verifier can look it up later.
            # We keep a copy of the entry with key ID inserted into metadata
            # before computing the HMAC, so the HMAC covers it.
            entry_with_key = replace(
                entry,
                metadata={**entry.metadata, KEY_ID_FIELD: active.key_id},
                prev_hmac=prev_hmac,
            )

            payload = _serialize_for_signing(entry_with_key)
            new_hmac = hmac.new(active.secret, payload, hashlib.sha256).hexdigest()

            linked = entry_with_key.with_chain_links(prev_hmac=prev_hmac, hmac=new_hmac)
            self._backend.append(linked)
            self._cached_prev = new_hmac
            return linked

    def _read_prev_hmac(self) -> str:
        """Return the HMAC of the latest entry in the chain, or ``""`` if
        the chain is empty. Cached after first read."""
        if self._cached_prev is not None:
            return self._cached_prev
        last = self._backend.last_entry()
        self._cached_prev = last.hmac if last is not None else ""
        return self._cached_prev


def _serialize_for_signing(entry: AuditEntry) -> bytes:
    """Canonical serialization of an entry for HMAC computation.

    Excludes the ``hmac`` field (since that's what we're computing).
    Includes everything else, including ``prev_hmac``, so chain breaks
    are detected.

    Canonicalization rules — these are deliberately narrow because the
    payload shape is constrained (see :class:`AuditEntry.to_dict`):

    * ``sort_keys=True`` — deterministic key order across runs.
    * ``separators=(",", ":")`` — no whitespace.
    * ``allow_nan=False`` — reject ``NaN`` / ``Infinity`` outright;
      they have no JSON literal and produce non-canonical output in
      Python's ``json`` (it emits ``NaN`` which strict parsers reject).
      A check that puts a NaN into metadata will fail loudly here
      rather than silently produce an unverifiable entry.
    * ``ensure_ascii=False`` — UTF-8 throughout. Callers that mix
      Unicode-normalization forms (NFC vs NFD) in metadata strings
      will produce different signatures for visually-identical text;
      normalize at the application layer if that matters.

    For richer canonicalization (RFC 8785 JCS, CBOR-deterministic),
    swap this function out — :class:`HmacChain` and
    :class:`ChainVerifier` import it as a module-level callable.
    """
    d: dict[str, Any] = entry.to_dict()
    d.pop("hmac", None)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")
