"""ChainVerifier — walks an audit chain and reports tampering.

Verification is read-only and offline: given a backend and a key ring,
walk every entry in order, recompute its HMAC, check the recomputed value
against the stored ``hmac``, and check the stored ``prev_hmac`` against
the previous entry's ``hmac``. Any mismatch is a *break*.

Returns a :class:`VerificationReport` with structured per-break detail.
The report distinguishes:

* **Self-mismatch** — the entry's own payload was modified (its HMAC
  doesn't match its content).
* **Link-mismatch** — the entry's ``prev_hmac`` doesn't match the
  previous entry's ``hmac``. Indicates insertion, deletion, or
  reordering.
* **Unknown-key** — the entry's signing key ID is not in the ring; we
  can't verify it. Distinct from a tamper finding: usually means the
  ring is missing a legacy key.

The CLI surfaces this through ``signet audit verify``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import StrEnum

from signet.audit.backend import AuditBackend
from signet.audit.chain import KEY_ID_FIELD, _serialize_for_signing
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry


class BreakKind(StrEnum):
    """Discriminator for the kind of integrity failure encountered."""

    SELF_MISMATCH = "self_mismatch"
    """The entry's stored HMAC does not match a recomputation from its
    payload + prev_hmac. The entry was modified after writing."""

    LINK_MISMATCH = "link_mismatch"
    """The entry's prev_hmac does not match the previous entry's hmac.
    Indicates insertion, deletion, or reordering somewhere in the chain."""

    UNKNOWN_KEY = "unknown_key"
    """The entry references a signing key ID not present in the
    :class:`KeyRing`. Verification cannot proceed for this entry."""

    MISSING_KEY_ID = "missing_key_id"
    """The entry has no signing-key-id metadata field. Either pre-dates
    the chain feature or was tampered to drop the marker."""


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """One integrity failure in the chain."""

    index: int
    """Zero-based position of the entry within the chain."""

    entry_id: str
    """The audit entry's UUID. Useful for cross-referencing with
    application logs."""

    kind: BreakKind
    """What kind of break this is."""

    detail: str
    """Human-readable rationale, including expected/actual fragments
    where relevant."""


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The output of :meth:`ChainVerifier.verify`.

    Attributes:
        total_entries: Number of entries walked.
        breaks: Per-entry integrity failures, in chain order.
        last_known_good_index: Index of the last entry that verified
            cleanly. ``-1`` if no entry verified.
        last_known_good_hmac: HMAC of the last entry that verified
            cleanly. Empty string if no entry verified.
    """

    total_entries: int
    breaks: tuple[ChainBreak, ...] = field(default_factory=tuple)
    last_known_good_index: int = -1
    last_known_good_hmac: str = ""

    @property
    def ok(self) -> bool:
        """``True`` if no breaks were detected."""
        return len(self.breaks) == 0


class ChainVerifier:
    """Walk a backend's chain end-to-end and report any tampering."""

    def __init__(self, backend: AuditBackend, keyring: KeyRing) -> None:
        self._backend = backend
        self._keyring = keyring

    def verify(self) -> VerificationReport:
        """Walk every entry in order and return a structured report."""
        breaks: list[ChainBreak] = []
        prev_hmac = ""
        last_good_idx = -1
        last_good_hmac = ""

        for index, entry in enumerate(self._backend.iter_entries()):
            # Link check: this entry's prev_hmac must match the prior entry's hmac
            if entry.prev_hmac != prev_hmac:
                breaks.append(
                    ChainBreak(
                        index=index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.LINK_MISMATCH,
                        detail=(
                            f"prev_hmac={entry.prev_hmac[:16]}... does not match "
                            f"previous entry's hmac={prev_hmac[:16] or '(empty)'}..."
                        ),
                    )
                )

            # Identify which key signed this entry
            key_id = entry.metadata.get(KEY_ID_FIELD)
            if not key_id:
                breaks.append(
                    ChainBreak(
                        index=index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.MISSING_KEY_ID,
                        detail=f"entry has no {KEY_ID_FIELD!r} field in metadata",
                    )
                )
                prev_hmac = entry.hmac
                continue

            key = self._keyring.get(key_id)
            if key is None:
                breaks.append(
                    ChainBreak(
                        index=index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.UNKNOWN_KEY,
                        detail=(
                            f"entry signed with key_id={key_id!r} but that key is "
                            f"not in the ring (known: {', '.join(self._keyring.all_known_ids())})"
                        ),
                    )
                )
                prev_hmac = entry.hmac
                continue

            # Self check: recompute the HMAC and compare
            expected_payload = _serialize_for_signing(entry)
            expected_hmac = hmac.new(key.secret, expected_payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_hmac, entry.hmac):
                breaks.append(
                    ChainBreak(
                        index=index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.SELF_MISMATCH,
                        detail=(
                            f"recomputed hmac={expected_hmac[:16]}... does not match "
                            f"stored hmac={entry.hmac[:16]}..."
                        ),
                    )
                )
            else:
                last_good_idx = index
                last_good_hmac = entry.hmac

            prev_hmac = entry.hmac

        return VerificationReport(
            total_entries=index + 1 if "index" in locals() else 0,
            breaks=tuple(breaks),
            last_known_good_index=last_good_idx,
            last_known_good_hmac=last_good_hmac,
        )


# Helper imported at top of file but referenced via private name; expose to
# tests and callers that build entries outside HmacChain (rare).
__all__ = [
    "BreakKind",
    "ChainBreak",
    "ChainVerifier",
    "VerificationReport",
]


def _entry_payload(entry: AuditEntry) -> bytes:
    """Re-export of the canonical serializer for test convenience."""
    return _serialize_for_signing(entry)
