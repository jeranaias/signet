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
from typing import Any, cast

from signet.audit.anchor import (
    ANCHOR_FIELD,
    AnchorBackend,
    AnchorProtocolError,
    AnchorReceipt,
    NoopAnchor,
)
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

        Concurrency: the in-process :class:`threading.Lock` serializes
        callers within one process. When ``cache_prev=False`` AND the
        backend exposes :meth:`append_locked_with_link` (i.e.
        :class:`FileLockingJsonlBackend`), the read-prev / compute /
        write sequence runs INSIDE the cross-process file lock so
        sibling worker processes cannot fork the chain. Without
        ``append_locked_with_link`` -- e.g. for custom backends -- we
        fall back to the legacy pattern: read prev outside the lock,
        write inside. That fallback is single-process safe via
        ``self._lock`` but susceptible to multi-process forks; document
        the limitation on the custom backend.
        """
        with self._lock:
            if not self._cache_prev and hasattr(self._backend, "append_locked_with_link"):
                # V2 (v0.1.7 follow-up): atomic multi-process path.
                # The ``hasattr`` gate above narrows to the
                # ``FileLockingJsonlBackend`` shape at runtime, but
                # mypy sees ``self._backend`` as the abstract
                # ``AuditBackend`` and treats the dynamic method call
                # as returning ``Any``. ``cast`` makes the return
                # type explicit; the runtime check is the actual
                # safety net.
                linked = cast(
                    AuditEntry,
                    self._backend.append_locked_with_link(
                        lambda prev: self._build_linked_entry(entry, prev)
                    ),
                )
                self._cached_prev = linked.hmac
                return linked

            # Legacy single-process / non-FileLockingJsonlBackend path.
            prev_hmac = self._read_prev_hmac()
            linked = self._build_linked_entry(entry, prev_hmac)
            self._backend.append(linked)
            self._cached_prev = linked.hmac
            return linked

    def _build_linked_entry(self, entry: AuditEntry, prev_hmac: str) -> AuditEntry:
        """Run the full sign-and-anchor pipeline against a known ``prev_hmac``.

        Factored out of :meth:`append` so the V2 atomic path
        (:meth:`FileLockingJsonlBackend.append_locked_with_link`) can
        invoke the same sequence inside the cross-process lock with the
        freshly-read tail HMAC.

        Raises ``RuntimeError`` when the anchor backend fails and
        ``require_anchor_success=True``.
        """
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
            anchor_receipt = AnchorReceipt(
                backend=self._anchor.name,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        # F-R5-A: defend against custom anchor backends that return
        # something that isn't an AnchorReceipt. Without this, the
        # downstream ``.success`` / ``.to_dict()`` accesses would surface
        # as raw AttributeError and corrupt the calling check's error
        # reporting (the operator sees a Python traceback, not a clean
        # protocol error).
        if not isinstance(anchor_receipt, AnchorReceipt):
            err = AnchorProtocolError(
                backend=self._anchor.name,
                field="<return value>",
                detail=(f"expected AnchorReceipt, got {type(anchor_receipt).__name__}"),
            )
            if self._require_anchor_success:
                raise err
            logger.warning(
                "anchor backend %s returned %s instead of AnchorReceipt; "
                "recording failure on entry",
                self._anchor.name,
                type(anchor_receipt).__name__,
            )
            anchor_receipt = AnchorReceipt(
                backend=self._anchor.name,
                success=False,
                error=str(err),
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
        return entry_with_anchor.with_chain_links(prev_hmac=prev_hmac, hmac=new_hmac)

    def _read_prev_hmac(self) -> str:
        """Return the HMAC the next append must link to, or ``""`` if
        the chain is empty.

        With ``cache_prev=True`` (default, single-process), cached after
        first read. With ``cache_prev=False`` (multi-process), always
        re-reads from the backend to pick up writes from sibling workers.

        Round 11 HIGH-1: marker-aware tail read. If the on-disk tail is
        a compaction marker (full-sweep result: the live log contains
        ONLY the marker), the correct predecessor for the next live
        append is the LAST ARCHIVED entry's hmac, NOT the marker's hmac.
        The marker's signed payload commits to that bridge value via its
        own ``prev_hmac`` field (set to ``eligible[-1].hmac`` by the
        compactor), so ``last.prev_hmac`` is exactly the bridge value
        the verifier's archive-bridge rule expects.

        This works regardless of ``cache_prev`` and survives process
        restart, because the bridge value is read directly from the
        marker on disk. The same-instance cache-seed in
        :func:`compact_audit_log` remains as a fast-path optimization
        (it avoids the linear scan), but the slow path is now correct
        on its own. An attacker cannot redirect the bridge without
        breaking the marker's own self-HMAC: the marker's payload
        (including its ``prev_hmac``) is bound by the chain HMAC under
        the keyring secret, so tampering shows up as ``SELF_MISMATCH``
        at verify time.
        """
        if self._cache_prev and self._cached_prev is not None:
            return self._cached_prev
        last = self._backend.last_entry()
        if last is None:
            prev = ""
        elif _tail_is_marker(last):
            # Full-sweep tail: bridge value = marker.prev_hmac.
            prev = last.prev_hmac
        else:
            prev = last.hmac
        if self._cache_prev:
            self._cached_prev = prev
        return prev


def _tail_is_marker(entry: AuditEntry) -> bool:
    """Round 11 HIGH-1: marker-aware tail detection for chain extension.

    Returns True when ``entry`` has compaction-marker shape. Used by
    :meth:`HmacChain._read_prev_hmac` (and by
    :meth:`FileLockingJsonlBackend._read_tail_hmac`) to decide whether
    the next live append should link to ``entry.hmac`` (ordinary tail)
    or to ``entry.prev_hmac`` (bridge value the marker commits to).

    Implemented as a lazy import of :func:`signet.audit.compactor._has_marker_shape`
    to avoid the chain → compactor → chain circular import at module
    load time. The check itself is a cheap structural test, and a stale
    cached miss would surface as ``LINK_MISMATCH`` immediately at the
    next verifier walk, so optimizing the import-cost away with a local
    duplicate isn't worth the desynchronization risk.
    """
    from signet.audit.compactor import _has_marker_shape

    return _has_marker_shape(entry)


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
