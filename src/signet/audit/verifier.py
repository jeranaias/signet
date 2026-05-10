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
* **Missing-key-id** — the entry has no signing-key-id metadata field.
  Either pre-dates the chain feature or was tampered to drop the marker.
* **Merkle-mismatch** — a compaction marker's claimed Merkle root does
  not match the recomputed root over the linked archive's contents.
  Surfaced by :func:`verify_with_archives` only.
* **Archive-missing** — a compaction marker references an archive file
  that is not present in the supplied ``archive_dir``. Surfaced by
  :func:`verify_with_archives` only.
* **Archive-format-invalid** — an archive file exists but cannot be
  parsed (truncated, wrong magic, version mismatch, internal-root
  mismatch). Surfaced by :func:`verify_with_archives` only.

The CLI surfaces this through ``signet audit verify`` and (with
archive walking) ``signet audit verify --including-archives``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from signet.audit.backend import AuditBackend, MalformedAuditEntry
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

    MERKLE_MISMATCH = "merkle_mismatch"
    """A compaction marker's claimed Merkle root does not match the
    root recomputed from the archive's contents. The archive or marker
    was tampered with after compaction."""

    ARCHIVE_MISSING = "archive_missing"
    """A compaction marker references an archive file not present in
    the supplied archive directory. Either the archive was deleted, or
    the operator pointed the verifier at the wrong directory."""

    ARCHIVE_FORMAT_INVALID = "archive_format_invalid"
    """An archive file is present but malformed — bad magic prefix,
    unknown format version, or truncated payload. Treat as a tamper
    finding; archives are written deterministically so a corrupt one
    means human or hardware interference."""

    MALFORMED_LINE = "malformed_line"
    """A line in the live log is not parseable JSON — mid-write
    truncation (process killed during ``fsync``), accidental editor
    save, or hostile injection of a non-JSON line. Reported with the
    1-based line number and the underlying parse error so the operator
    can locate it. Iteration stops at the offending line; subsequent
    entries are not visible until the line is repaired."""

    CASCADE_SUPPRESSED = "cascade_suppressed"
    """A summary break standing in for ``N`` downstream
    ``LINK_MISMATCH`` entries that all cascade from a single upstream
    forgery / tamper / link break. Emitted only when the verifier is
    asked to compact reports (``compact_breaks=True``) so a 1k-entry
    forgery doesn't drown the report in 1k+ identical-shaped breaks."""


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

    def __init__(
        self,
        backend: AuditBackend,
        keyring: KeyRing,
        *,
        compact_breaks: bool = False,
    ) -> None:
        """Walk ``backend`` under ``keyring`` and report integrity failures.

        Args:
            backend: The audit backend to read from.
            keyring: The signing keys covering the chain.
            compact_breaks: When True, collapse cascading
                :attr:`BreakKind.LINK_MISMATCH` runs that follow a
                single upstream tamper into one
                :attr:`BreakKind.CASCADE_SUPPRESSED` summary break.
                Useful for keeping large-chain reports readable when a
                single forgery would otherwise surface as N+ link
                breaks. Default False preserves v0.1.6 behavior.
        """
        self._backend = backend
        self._keyring = keyring
        self._compact_breaks = compact_breaks

    def verify(self) -> VerificationReport:
        """Walk every entry in order and return a structured report."""
        breaks: list[ChainBreak] = []
        prev_hmac = ""
        last_good_idx = -1
        last_good_hmac = ""
        total_entries = 0
        # A11: when compact_breaks is on, runs of consecutive
        # LINK_MISMATCH entries downstream of a tamper get collapsed
        # into a single CASCADE_SUPPRESSED summary break.
        cascade_active = False
        cascade_count = 0
        cascade_first_idx = -1

        def _flush_cascade() -> None:
            nonlocal cascade_active, cascade_count, cascade_first_idx
            if cascade_active and cascade_count > 0:
                breaks.append(
                    ChainBreak(
                        index=cascade_first_idx,
                        entry_id="",
                        kind=BreakKind.CASCADE_SUPPRESSED,
                        detail=(
                            f"{cascade_count} downstream entries reported "
                            f"link_mismatch cascading from upstream tamper; "
                            f"individual breaks suppressed (compact_breaks=True)"
                        ),
                    )
                )
            cascade_active = False
            cascade_count = 0
            cascade_first_idx = -1

        try:
            for index, entry in enumerate(self._backend.iter_entries()):
                total_entries = index + 1
                # A6: track whether THIS entry already produced a
                # link_mismatch — when it has, the self_mismatch on
                # the same index is suppressed because both checks
                # share an input (``prev_hmac`` is part of the signed
                # payload), so a single-byte tamper naturally trips
                # both. The report reader expects one canonical break.
                link_break_at_this_index = False
                # Link check: this entry's prev_hmac must match the prior entry's hmac
                if entry.prev_hmac != prev_hmac:
                    if self._compact_breaks and cascade_active:
                        cascade_count += 1
                    else:
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
                        if self._compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = index + 1
                    link_break_at_this_index = True
                else:
                    # A clean link ends any active cascade.
                    _flush_cascade()

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
                    if not link_break_at_this_index:
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
        except MalformedAuditEntry as exc:
            # A3: turn a malformed JSONL line into a structured break
            # rather than letting JSONDecodeError propagate. Iteration
            # stops at the bad line — the rest of the file is opaque
            # until the operator repairs the line. Subsequent entries
            # are not reported.
            breaks.append(
                ChainBreak(
                    index=total_entries,
                    entry_id="",
                    kind=BreakKind.MALFORMED_LINE,
                    detail=(
                        f"line {exc.line_number}: cannot parse as JSON: "
                        f"{exc.parse_error}"
                    ),
                )
            )
        finally:
            _flush_cascade()

        return VerificationReport(
            total_entries=total_entries,
            breaks=tuple(breaks),
            last_known_good_index=last_good_idx,
            last_known_good_hmac=last_good_hmac,
        )


def _verify_entry_self(
    *,
    index: int,
    entry: AuditEntry,
    keyring: KeyRing,
    breaks: list[ChainBreak],
    suppress_self_mismatch: bool = False,
) -> bool:
    """Verify one entry's self-HMAC. Append a break on failure.

    Returns True if the entry's signing key was found and the HMAC
    matched, False otherwise. The link check is the caller's
    responsibility — link semantics differ between the simple
    walker and the archive-aware walker.

    ``suppress_self_mismatch`` (A6): when True, an HMAC mismatch is
    NOT reported as a separate ``SELF_MISMATCH`` break — the caller
    has already reported a ``LINK_MISMATCH`` for this entry and the
    two checks share an input (``prev_hmac`` is part of the signed
    payload), so a single byte of tampering naturally trips both.
    The function still returns False so cascade tracking and
    last-known-good bookkeeping behave correctly.
    """
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
        return False
    key = keyring.get(key_id)
    if key is None:
        breaks.append(
            ChainBreak(
                index=index,
                entry_id=entry.entry_id,
                kind=BreakKind.UNKNOWN_KEY,
                detail=(
                    f"entry signed with key_id={key_id!r} but that key is "
                    f"not in the ring (known: {', '.join(keyring.all_known_ids())})"
                ),
            )
        )
        return False

    expected_payload = _serialize_for_signing(entry)
    expected_hmac = hmac.new(key.secret, expected_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, entry.hmac):
        if not suppress_self_mismatch:
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
        return False
    return True


def verify_with_archives(
    backend: AuditBackend,
    keyring: KeyRing,
    archive_dir: Path,
    *,
    compact_breaks: bool = False,
) -> VerificationReport:
    """Walk the live log + every referenced archive as one logical chain.

    On each compaction marker encountered in the live log, this
    verifier:

    1. Looks up the marker's referenced archive in ``archive_dir``.
    2. Reads the archive and recomputes the Merkle root from its
       contents.
    3. Compares the recomputed root against the marker's claimed root.
       Mismatch → :attr:`BreakKind.MERKLE_MISMATCH`.
    4. Verifies each archived entry's self-HMAC and internal link
       chain. Any failure is reported with the entry's archive index
       (offset from the start of the archive's entries) and an
       ``in archive <name>`` annotation in the detail string.
    5. Validates that the marker's ``prev_hmac`` matches the LAST
       archived entry's ``hmac`` (the bridge from live log into
       archive).
    6. After the marker, the next live-log entry is treated as the
       continuation of the archive: its ``prev_hmac`` MUST match the
       last archived entry's ``hmac``. This is the bridge from archive
       back into the live log.

    The "live-only" :class:`ChainVerifier` is unchanged. Use it when
    you only need to walk the trimmed live log (cheap) and don't have
    the archives accessible. Use this function for the full-chain
    verification path that ``signet audit verify --including-archives``
    exposes.

    Missing archive (marker references ``archive-X.bin`` but the file
    isn't on disk) → :attr:`BreakKind.ARCHIVE_MISSING`. Malformed
    archive → :attr:`BreakKind.ARCHIVE_FORMAT_INVALID`.

    Args:
        backend: The (post-compaction) live log backend.
        keyring: The signing keys covering the entire logical chain,
            including any keys in use during the archived ranges.
        archive_dir: Directory containing the archive files referenced
            by every compaction marker in the live log. The marker's
            ``archive_path`` may be absolute or relative; the verifier
            tries the absolute path first, then ``archive_dir / Path(
            absolute).name``.
        compact_breaks: When True (A11), runs of consecutive
            :attr:`BreakKind.LINK_MISMATCH` entries downstream of a
            single tamper are collapsed into one
            :attr:`BreakKind.CASCADE_SUPPRESSED` summary break.

    Returns:
        A :class:`VerificationReport`. ``total_entries`` is the count
        across all segments (live log + every archive), so a chain
        with one archive of 47k entries plus 3k live entries reports
        50k.
    """
    # Local imports keep this module's import surface narrow for callers
    # that only use the live-only verifier.
    from signet.audit.compactor import (
        COMPACTION_MARKER_FIELD,
        MerkleTree,
        is_compaction_marker,
        read_archive,
    )

    archive_dir = Path(archive_dir)
    breaks: list[ChainBreak] = []
    total_entries = 0
    last_known_good_index = -1
    last_known_good_hmac = ""
    # The expected prev_hmac for the next entry we encounter. Updated
    # as we walk, including across the archive bridge.
    expected_prev = ""
    # Logical index across the whole chain (live + archives).
    logical_index = 0
    # A11 cascade tracking — same shape as the live-only verifier.
    cascade_active = False
    cascade_count = 0
    cascade_first_idx = -1

    def _flush_cascade() -> None:
        nonlocal cascade_active, cascade_count, cascade_first_idx
        if cascade_active and cascade_count > 0:
            breaks.append(
                ChainBreak(
                    index=cascade_first_idx,
                    entry_id="",
                    kind=BreakKind.CASCADE_SUPPRESSED,
                    detail=(
                        f"{cascade_count} downstream entries reported "
                        f"link_mismatch cascading from upstream tamper; "
                        f"individual breaks suppressed (compact_breaks=True)"
                    ),
                )
            )
        cascade_active = False
        cascade_count = 0
        cascade_first_idx = -1

    try:
        for entry in backend.iter_entries():
            if not is_compaction_marker(entry):
                # Plain live entry: standard self + link checks.
                link_break_at_this_index = False
                if entry.prev_hmac != expected_prev:
                    if compact_breaks and cascade_active:
                        cascade_count += 1
                    else:
                        breaks.append(
                            ChainBreak(
                                index=logical_index,
                                entry_id=entry.entry_id,
                                kind=BreakKind.LINK_MISMATCH,
                                detail=(
                                    f"prev_hmac={entry.prev_hmac[:16]}... does not match "
                                    f"expected previous hmac={expected_prev[:16] or '(empty)'}..."
                                ),
                            )
                        )
                        if compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = logical_index + 1
                    link_break_at_this_index = True
                else:
                    _flush_cascade()
                ok = _verify_entry_self(
                    index=logical_index,
                    entry=entry,
                    keyring=keyring,
                    breaks=breaks,
                    suppress_self_mismatch=link_break_at_this_index,
                )
                if ok:
                    last_known_good_index = logical_index
                    last_known_good_hmac = entry.hmac
                total_entries += 1
                logical_index += 1
                expected_prev = entry.hmac
                continue

            # Compaction marker. Walk the archive first so we have its
            # last hmac to use both for the marker's own link check and
            # for the bridge to the next live entry.
            marker_meta = entry.metadata[COMPACTION_MARKER_FIELD]
            archive_path_str = str(marker_meta.get("archive_path", ""))
            claimed_root = str(marker_meta.get("merkle_root", ""))
            claimed_count = int(marker_meta.get("compacted_count", 0))

            # Resolve the archive: try the absolute path embedded in the
            # marker first, then fall back to archive_dir/<basename>. This
            # keeps deployments working when the audit log is moved
            # between machines (the absolute path is no longer valid but
            # the basename is stable).
            archive_path = Path(archive_path_str)
            if not archive_path.exists():
                fallback = archive_dir / archive_path.name
                if fallback.exists():
                    archive_path = fallback
                else:
                    breaks.append(
                        ChainBreak(
                            index=logical_index,
                            entry_id=entry.entry_id,
                            kind=BreakKind.ARCHIVE_MISSING,
                            detail=(
                                f"compaction marker references archive {archive_path_str!r} "
                                f"but neither it nor {fallback} exists"
                            ),
                        )
                    )
                    # Without the archive we can't bridge. Verify the
                    # marker's self-HMAC (still meaningful) and continue
                    # with expected_prev = marker.hmac so subsequent live
                    # entries don't all cascade as link breaks. This is
                    # operationally inaccurate (the next live entry
                    # actually links to last_archived.hmac, not
                    # marker.hmac) but it produces one ARCHIVE_MISSING
                    # break per missing archive instead of N+1 cascading
                    # breaks per live entry.
                    _verify_entry_self(
                        index=logical_index,
                        entry=entry,
                        keyring=keyring,
                        breaks=breaks,
                    )
                    total_entries += 1
                    logical_index += 1
                    expected_prev = entry.hmac
                    continue

            try:
                header, tree, archived_entries = read_archive(archive_path)
            except ValueError as exc:
                breaks.append(
                    ChainBreak(
                        index=logical_index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.ARCHIVE_FORMAT_INVALID,
                        detail=f"archive {archive_path.name}: {exc}",
                    )
                )
                _verify_entry_self(
                    index=logical_index,
                    entry=entry,
                    keyring=keyring,
                    breaks=breaks,
                )
                total_entries += 1
                logical_index += 1
                expected_prev = entry.hmac
                continue

            # Walk the archived entries first, in their own logical-index
            # range that comes BEFORE the marker. This is what the format
            # spec calls "logical chain order": archived entries come
            # before the marker that summarizes them, even though the
            # marker is the entry physically at the top of the post-
            # compaction live log.
            archive_base_index = logical_index
            archive_expected_prev = expected_prev
            for archive_idx, archived in enumerate(archived_entries):
                archive_link_break = False
                if archived.prev_hmac != archive_expected_prev:
                    if compact_breaks and cascade_active:
                        cascade_count += 1
                    else:
                        breaks.append(
                            ChainBreak(
                                index=archive_base_index + archive_idx,
                                entry_id=archived.entry_id,
                                kind=BreakKind.LINK_MISMATCH,
                                detail=(
                                    f"archive {archive_path.name} entry {archive_idx}: "
                                    f"prev_hmac={archived.prev_hmac[:16]}... does not match "
                                    f"expected={archive_expected_prev[:16] or '(empty)'}..."
                                ),
                            )
                        )
                        if compact_breaks:
                            cascade_active = True
                            cascade_count = 0
                            cascade_first_idx = archive_base_index + archive_idx + 1
                    archive_link_break = True
                else:
                    _flush_cascade()
                archive_ok = _verify_entry_self(
                    index=archive_base_index + archive_idx,
                    entry=archived,
                    keyring=keyring,
                    breaks=breaks,
                    suppress_self_mismatch=archive_link_break,
                )
                if archive_ok:
                    last_known_good_index = archive_base_index + archive_idx
                    last_known_good_hmac = archived.hmac
                archive_expected_prev = archived.hmac

            last_archived_hmac = archived_entries[-1].hmac if archived_entries else ""

            # Recompute the Merkle root from the archive's contents and
            # compare against the marker's claim. A mismatch can come from
            # (a) the marker being modified, (b) the archive being modified,
            # or (c) the archive's serialized tree being modified — the
            # deserialize step asserts the stored root matches the
            # recomputation, so (c) is already an ARCHIVE_FORMAT_INVALID.
            recomputed_tree = MerkleTree.from_entries(archived_entries)
            if (
                recomputed_tree.root != claimed_root
                or header.merkle_root != claimed_root
                or tree.root != claimed_root
            ):
                breaks.append(
                    ChainBreak(
                        index=archive_base_index + len(archived_entries),
                        entry_id=entry.entry_id,
                        kind=BreakKind.MERKLE_MISMATCH,
                        detail=(
                            f"archive {archive_path.name} merkle root "
                            f"recomputed={recomputed_tree.root[:16]}... does not match "
                            f"marker's claim={claimed_root[:16]}..."
                        ),
                    )
                )

            if len(archived_entries) != claimed_count:
                breaks.append(
                    ChainBreak(
                        index=archive_base_index + len(archived_entries),
                        entry_id=entry.entry_id,
                        kind=BreakKind.ARCHIVE_FORMAT_INVALID,
                        detail=(
                            f"archive {archive_path.name} contains "
                            f"{len(archived_entries)} entries but marker claims "
                            f"{claimed_count}"
                        ),
                    )
                )

            # Marker's link check: prev_hmac MUST equal the last archived
            # entry's hmac. This is the live-log → archive bridge.
            marker_logical_index = archive_base_index + len(archived_entries)
            marker_link_break = False
            if entry.prev_hmac != last_archived_hmac:
                breaks.append(
                    ChainBreak(
                        index=marker_logical_index,
                        entry_id=entry.entry_id,
                        kind=BreakKind.LINK_MISMATCH,
                        detail=(
                            f"compaction marker's prev_hmac={entry.prev_hmac[:16]}... "
                            f"does not bridge to last archived entry's "
                            f"hmac={last_archived_hmac[:16]}... in {archive_path.name}"
                        ),
                    )
                )
                marker_link_break = True

            marker_ok = _verify_entry_self(
                index=marker_logical_index,
                entry=entry,
                keyring=keyring,
                breaks=breaks,
                suppress_self_mismatch=marker_link_break,
            )
            if marker_ok:
                last_known_good_index = marker_logical_index
                last_known_good_hmac = entry.hmac

            # Bridge from archive back to live log: the next live entry's
            # prev_hmac must equal the LAST ARCHIVED entry's hmac, NOT the
            # marker's hmac. (Both the marker and the next live entry
            # share the same predecessor — that's the documented fork.)
            expected_prev = last_archived_hmac
            total_entries += len(archived_entries) + 1  # +1 for the marker
            logical_index = marker_logical_index + 1
    except MalformedAuditEntry as exc:
        # A3 (archive walker): a malformed JSONL line in the live log
        # surfaces as a structured break, just like the live-only
        # walker. Iteration stops there.
        breaks.append(
            ChainBreak(
                index=logical_index,
                entry_id="",
                kind=BreakKind.MALFORMED_LINE,
                detail=(
                    f"line {exc.line_number}: cannot parse as JSON: "
                    f"{exc.parse_error}"
                ),
            )
        )
    finally:
        _flush_cascade()

    return VerificationReport(
        total_entries=total_entries,
        breaks=tuple(breaks),
        last_known_good_index=last_known_good_index,
        last_known_good_hmac=last_known_good_hmac,
    )


__all__ = [
    "BreakKind",
    "ChainBreak",
    "ChainVerifier",
    "VerificationReport",
    "verify_with_archives",
]
