"""HmacChain — the writer that signs audit entries and links them.

Each appended entry's HMAC depends on:

1. The entry's own payload (everything except the ``hmac`` field itself).
2. The HMAC of the previous entry, carried in ``prev_hmac``.

Tampering with any entry breaks its own HMAC; tampering further back
breaks every entry afterwards because the chain link no longer matches.
The verifier in :mod:`signet.audit.verifier` walks the chain and reports
exactly where a break occurs.

Threading: a single :class:`HmacChain` instance is not safe for concurrent
appends. For multi-process or multi-threaded writers, either serialize
through a queue or partition writers by chain (one chain per writer).
"""

from __future__ import annotations

import hashlib
import hmac
import json
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

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Sign and persist ``entry``; return the linked entry.

        The returned entry has ``prev_hmac``, ``hmac``, and the signing
        key ID populated. The original ``entry`` argument is unchanged
        (entries are frozen).
        """
        prev_hmac = self._read_prev_hmac()
        active = self._keyring.active

        # Embed the signing key ID so the verifier can look it up later.
        # We keep a copy of the entry with key ID inserted into metadata
        # before computing the HMAC, so the HMAC covers it.
        from dataclasses import replace

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
    are detected. Uses sort_keys + compact separators for determinism
    across implementations and Python versions.
    """
    d: dict[str, Any] = entry.to_dict()
    d.pop("hmac", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
