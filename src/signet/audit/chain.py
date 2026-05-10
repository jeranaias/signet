"""HmacChain -- the writer that signs audit entries and links them.

Each appended entry's HMAC depends on:

1. The entry's own payload (everything except the ``hmac`` field itself).
2. The HMAC of the previous entry, carried in ``prev_hmac``.

Tampering with any entry breaks its own HMAC; tampering further back
breaks every entry afterwards because the chain link no longer matches.
The verifier in :mod:`signet.audit.verifier` walks the chain and reports
exactly where a break occurs.

Concurrency:

* **In-process:** ``append`` holds an internal :class:`threading.Lock`
  so single-process concurrent callers (FastAPI's async event loop
  counts as one) cannot fork the chain by reading the same
  ``prev_hmac`` twice before either writes.
* **Multi-process** (uvicorn ``--workers N>1``): pair this with
  :class:`signet.audit.backend.FileLockingJsonlBackend` and pass
  ``cache_prev=False`` to disable the in-process prev-cache. The
  chain will then re-read the chain head under the cross-process lock
  on every append, ensuring per-worker views of ``prev_hmac`` stay
  consistent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from dataclasses import replace
from typing import Any

from signet.audit.anchor import ANCHOR_FIELD, AnchorBackend, NoopAnchor
from signet.audit.backend import AuditBackend
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry

logger = logging.getLogger("signet.audit.chain")

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

    External anchoring: pass an :class:`signet.audit.anchor.AnchorBackend`
    to bind each entry's HMAC to an external timestamp authority or
    transparency log. The anchor receipt is embedded in the entry's
    metadata under ``_anchor`` BEFORE the HMAC is computed, so the
    chain HMAC binds the receipt to the entry. With the default
    :class:`NoopAnchor`, behavior is byte-identical to v0.1.2 chains.
    """

    def __init__(
        self,
        backend: AuditBackend,
        keyring: KeyRing,
        *,
        anchor: AnchorBackend | None = None,
        require_anchor_success: bool = False,
        cache_prev: bool = True,
    ) -> None:
        self._backend = backend
        self._keyring = keyring
        self._anchor: AnchorBackend = anchor if anchor is not None else NoopAnchor()
        self._require_anchor_success = require_anchor_success
        # When True (default, single-process), cache the last entry's
        # HMAC so we don't scan the backend on every append. Set False
        # when running multiple writers against a FileLockingJsonlBackend
        # -- each append then re-reads the chain head under the
        # cross-process lock so workers stay consistent.
        self._cache_prev = cache_prev
        self._cached_prev: str | None = None
        # Serialize concurrent appends. Required because two coroutines
        # racing through read_prev → compute → write would otherwise both
        # see the same prev_hmac and fork the chain. See module docstring
        # for the multi-process caveat.
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry) -> AuditEntry:
        """Sign and persist ``entry``; return the linked entry.

        The returned entry has ``prev_hmac``, ``hmac``, the signing
        key ID, and (when an anchor backend is configured) an anchor
        receipt populated. The original ``entry`` argument is unchanged
        (entries are frozen).

        If ``require_anchor_success=True`` was passed at construction
        and the anchor backend reports failure, this method raises
        ``RuntimeError`` and the entry is NOT written to the backend.
        Default behavior (``require_anchor_success=False``) writes the
        entry with the failure recorded in ``metadata['_anchor']``.
        """
        with self._lock:
            prev_hmac = self._read_prev_hmac()
            active = self._keyring.active

            # First pass: compute a tentative HMAC over the payload
            # WITHOUT the anchor receipt. The tentative HMAC is what we
            # submit to the anchor backend -- anchoring the input to the
            # signing function, not the output, keeps the order of
            # operations clean (anchor commits to the entry's identity,
            # the chain HMAC commits to the anchor receipt + payload).
            tentative_with_key = replace(
                entry,
                metadata={**entry.metadata, KEY_ID_FIELD: active.key_id},
                prev_hmac=prev_hmac,
            )
            tentative_payload = _serialize_for_signing(tentative_with_key)
            tentative_hmac = hmac.new(active.secret, tentative_payload, hashlib.sha256).hexdigest()

            # Anchor the tentative HMAC. NoopAnchor returns success
            # immediately; real backends do an external HTTP call.
            try:
                anchor_receipt = self._anchor.anchor_hmac(tentative_hmac)
            except Exception as exc:
                if self._require_anchor_success:
                    raise
                logger.warning(
                    "anchor backend %s raised %s; recording failure on entry",
                    self._anchor.name,
                    type(exc).__name__,
                )
                from signet.audit.anchor import AnchorReceipt

                anchor_receipt = AnchorReceipt(
                    backend=self._anchor.name,
                    success=False,
                    error=f"{type(exc).__name__}: {exc}",
                )

            if not anchor_receipt.success and self._require_anchor_success:
                raise RuntimeError(
                    f"anchor backend {self._anchor.name!r} failed "
                    f"(require_anchor_success=True): {anchor_receipt.error}"
                )

            # Final pass: rebuild the entry with the anchor receipt in
            # metadata, then compute the chain HMAC over the full payload.
            anchored_metadata = {
                **entry.metadata,
                KEY_ID_FIELD: active.key_id,
                ANCHOR_FIELD: anchor_receipt.to_dict(),
            }
            entry_with_anchor = replace(
                entry,
                metadata=anchored_metadata,
                prev_hmac=prev_hmac,
            )
            payload = _serialize_for_signing(entry_with_anchor)
            new_hmac = hmac.new(active.secret, payload, hashlib.sha256).hexdigest()

            linked = entry_with_anchor.with_chain_links(prev_hmac=prev_hmac, hmac=new_hmac)
            self._backend.append(linked)
            self._cached_prev = new_hmac
            return linked

    def _read_prev_hmac(self) -> str:
        """Return the HMAC of the latest entry in the chain, or ``""`` if
        the chain is empty.

        With ``cache_prev=True`` (default, single-process), cached after
        first read. With ``cache_prev=False`` (multi-process), always
        re-reads from the backend to pick up writes from sibling workers.
        """
        if self._cache_prev and self._cached_prev is not None:
            return self._cached_prev
        last = self._backend.last_entry()
        prev = last.hmac if last is not None else ""
        if self._cache_prev:
            self._cached_prev = prev
        return prev


def _serialize_for_signing(entry: AuditEntry) -> bytes:
    """Canonical serialization of an entry for HMAC computation.

    Excludes the ``hmac`` field (since that's what we're computing).
    Includes everything else, including ``prev_hmac``, so chain breaks
    are detected.

    Canonicalization rules -- these are deliberately narrow because the
    payload shape is constrained (see :class:`AuditEntry.to_dict`):

    * ``sort_keys=True`` -- deterministic key order across runs.
    * ``separators=(",", ":")`` -- no whitespace.
    * ``allow_nan=False`` -- reject ``NaN`` / ``Infinity`` outright;
      they have no JSON literal and produce non-canonical output in
      Python's ``json`` (it emits ``NaN`` which strict parsers reject).
      A check that puts a NaN into metadata will fail loudly here
      rather than silently produce an unverifiable entry.
    * ``ensure_ascii=False`` -- UTF-8 throughout. Callers that mix
      Unicode-normalization forms (NFC vs NFD) in metadata strings
      will produce different signatures for visually-identical text;
      normalize at the application layer if that matters.

    For richer canonicalization (RFC 8785 JCS, CBOR-deterministic),
    swap this function out -- :class:`HmacChain` and
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
