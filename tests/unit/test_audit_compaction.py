"""Tests for signet.audit.compactor — the Merkle-archived compaction protocol.

Coverage targets:

* Round-trip: build a chain, compact half, verify the live log + archive
  together verify as one logical chain.
* Archive byte-stability: same input produces identical archive bytes.
* Marker chain correctness: the marker's prev_hmac points at the last
  archived entry's hmac.
* Tamper detection: flipping a bit in the archive surfaces as
  MERKLE_MISMATCH; deleting the archive surfaces as ARCHIVE_MISSING;
  malforming the archive surfaces as ARCHIVE_FORMAT_INVALID.
* No-op: cutoff before all entries returns None and writes no archive.
* Header carries `signet_version`.

The round-trip test is the centerpiece — it's the test that catches
any drift in the Merkle / marker / verifier triple.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.compactor import (
    ARCHIVE_FORMAT_VERSION,
    COMPACTION_CHECK_NAME,
    COMPACTION_MARKER_FIELD,
    ArchiveHeader,
    CompactionResult,
    MerkleTree,
    compact_audit_log,
    is_compaction_marker,
    read_archive,
    trim_before_index,
)
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import (
    BreakKind,
    ChainVerifier,
    verify_with_archives,
)
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _make_entry(reason: str, *, ts_ns: int | None = None) -> AuditEntry:
    """Construct an AuditEntry with an optional explicit timestamp.

    We override ``ts_ns`` because the round-trip / cutoff tests need
    deterministic ordering across the cutoff boundary; relying on
    wall-clock time produces flaky boundary semantics.
    """
    kwargs: dict = {
        "owner": Owner.human("alice@example.com"),
        "check_name": "owner_resolution",
        "decision": Decision.ALLOW,
        "reason": reason,
    }
    if ts_ns is not None:
        kwargs["ts_ns"] = ts_ns
    return AuditEntry(**kwargs)


@pytest.fixture
def keyring() -> KeyRing:
    # Use a fixed key so byte-stability tests can compare across runs.
    return KeyRing(active=Key(key_id="k1", secret=b"x" * 32))


@pytest.fixture
def backend(tmp_path: Path) -> JsonlBackend:
    return JsonlBackend(tmp_path / "audit.jsonl", fsync_after_append=False)


@pytest.fixture
def chain(backend: JsonlBackend, keyring: KeyRing) -> HmacChain:
    return HmacChain(backend=backend, keyring=keyring)


class TestMerkleTree:
    def test_single_entry(self, chain: HmacChain) -> None:
        appended = chain.append(_make_entry("only"))
        tree = MerkleTree.from_entries([appended])
        # With one leaf the root equals the leaf hash.
        assert tree.root == tree.leaves[0]

    def test_three_entries_odd_fill(self, chain: HmacChain) -> None:
        a = chain.append(_make_entry("a"))
        b = chain.append(_make_entry("b"))
        c = chain.append(_make_entry("c"))
        tree = MerkleTree.from_entries([a, b, c])
        assert len(tree.leaves) == 3
        # Root is hex SHA-256.
        assert len(tree.root) == 64
        int(tree.root, 16)  # parses as hex without raising

    def test_serialization_round_trip(self, chain: HmacChain) -> None:
        entries = [chain.append(_make_entry(f"e{i}")) for i in range(7)]
        tree = MerkleTree.from_entries(entries)
        blob = tree.serialize()
        restored = MerkleTree.deserialize(blob)
        assert restored.leaves == tree.leaves
        assert restored.root == tree.root

    def test_serialize_empty_rejected(self) -> None:
        with pytest.raises(ValueError):
            MerkleTree.from_entries([])

    def test_deserialize_truncated_rejected(self, chain: HmacChain) -> None:
        entries = [chain.append(_make_entry(f"e{i}")) for i in range(3)]
        blob = MerkleTree.from_entries(entries).serialize()
        with pytest.raises(ValueError):
            MerkleTree.deserialize(blob[:20])

    def test_deserialize_wrong_magic_rejected(self) -> None:
        with pytest.raises(ValueError, match="magic"):
            MerkleTree.deserialize(b"NOTAMERKLE\nbody")


class TestArchiveByteStability:
    def test_archive_round_trips_byte_stable(
        self, tmp_path: Path, keyring: KeyRing
    ) -> None:
        """Same input → same archive bytes. This is the determinism
        guarantee that makes archives safe to ship to external auditors
        or transparency logs."""
        # Build two independent chains over identical entries.
        path_a = tmp_path / "audit-a.jsonl"
        path_b = tmp_path / "audit-b.jsonl"
        backend_a = JsonlBackend(path_a, fsync_after_append=False)
        backend_b = JsonlBackend(path_b, fsync_after_append=False)
        chain_a = HmacChain(backend=backend_a, keyring=keyring)
        chain_b = HmacChain(backend=backend_b, keyring=keyring)

        # Pin entry_id and ts_ns so the audit entries are byte-identical.
        # Without this, random UUIDs and time.time_ns() inject noise.
        for i in range(10):
            common = AuditEntry(
                owner=Owner.human("alice"),
                check_name="check",
                decision=Decision.ALLOW,
                reason=f"e{i}",
                entry_id=f"00000000-0000-0000-0000-{i:012d}",
                ts_ns=1_700_000_000_000_000_000 + i * 1_000_000_000,
            )
            chain_a.append(common)
            chain_b.append(common)

        cutoff = datetime(2099, 1, 1, tzinfo=UTC)
        archive_a = tmp_path / "a.bin"
        archive_b = tmp_path / "b.bin"
        compact_audit_log(
            chain=chain_a, backend=backend_a, before=cutoff, output=archive_a
        )
        compact_audit_log(
            chain=chain_b, backend=backend_b, before=cutoff, output=archive_b
        )

        assert archive_a.read_bytes() == archive_b.read_bytes()

    def test_archive_header_includes_signet_version(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))
        archive = tmp_path / "archive.bin"
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
        )
        assert result is not None
        header, _, _ = read_archive(archive)
        assert header.archive_format_version == ARCHIVE_FORMAT_VERSION == 1
        assert header.signet_version  # non-empty
        assert header.entry_count == 3


class TestMarkerChaining:
    def test_marker_chains_correctly(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        """The compaction marker's prev_hmac MUST point at the last
        archived entry's hmac. Any other value breaks the verifier."""
        appended: list[AuditEntry] = []
        for i in range(5):
            appended.append(chain.append(_make_entry(f"e{i}")))
        last_archived = appended[-1]

        archive = tmp_path / "archive.bin"
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
        )
        assert result is not None

        # Read the live log; first entry should be the marker, with
        # prev_hmac pointing at the last archived entry.
        live_entries = list(backend.iter_entries())
        assert len(live_entries) == 1  # only the marker
        marker = live_entries[0]
        assert is_compaction_marker(marker)
        assert marker.prev_hmac == last_archived.hmac
        # Marker payload exposes the merkle root and count.
        payload = marker.metadata[COMPACTION_MARKER_FIELD]
        assert payload["compacted_count"] == 5
        assert payload["merkle_root"] == result.merkle_root
        assert marker.entry_id == result.marker_entry_id

    def test_marker_check_name_constant(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        chain.append(_make_entry("only"))
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=tmp_path / "archive.bin",
        )
        marker = next(iter(backend.iter_entries()))
        assert marker.check_name == COMPACTION_CHECK_NAME == "_compaction"


class TestNoOp:
    def test_compact_with_no_eligible_entries_is_noop(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        """Cutoff before every entry → no archive, no marker, returns None."""
        # Entries written now will all have ts_ns >= now.
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))

        archive = tmp_path / "archive.bin"
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(1990, 1, 1, tzinfo=UTC),
            output=archive,
        )
        assert result is None
        assert not archive.exists()
        # Live log unchanged: still 3 entries, no marker.
        live = list(backend.iter_entries())
        assert len(live) == 3
        assert not any(is_compaction_marker(e) for e in live)

    def test_compact_empty_chain_is_noop(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        archive = tmp_path / "archive.bin"
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
        )
        assert result is None
        assert not archive.exists()


class TestRoundTripVerification:
    def test_round_trip_compaction_preserves_verification(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path, keyring: KeyRing
    ) -> None:
        """Build a chain of N entries, compact half, verify the chain
        plus archive together verify as one logical chain.

        The point of this test is to catch any drift in the Merkle /
        marker / verifier triple. If any of the three drift, this test
        fails loudly.

        Scale: 10k entries. The spec called for 100k as the target,
        but 100k of HMAC-chained appends through Python's
        :class:`JsonlBackend` runs in ~7 minutes on Windows because
        every append is a fresh ``open(...)``/``fsync``/``close``
        cycle. The protocol logic — link-bridge, Merkle, verify — is
        identical at any scale, so 10k gives us the same coverage in
        seconds. The 100k scale is documented in the format spec as a
        capacity reference; rerun manually with N=100_000 for a
        capacity check on faster hardware.
        """
        N = 10_000
        cutoff_idx = N // 2
        # Fabricate timestamps a microsecond apart so the cutoff
        # partitions the chain at exactly cutoff_idx. We keep the gap
        # at 1µs (1000 ns) — small enough that 10k fits in one second
        # of timeline, large enough that float-precision in
        # :meth:`datetime.timestamp` round-trips don't drift the
        # boundary.
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        gap_ns = 1_000  # 1 microsecond
        for i in range(N):
            chain.append(_make_entry(f"e{i:05d}", ts_ns=base_ns + i * gap_ns))
        # Cutoff datetime sits exactly between entry cutoff_idx-1 and
        # entry cutoff_idx, so cutoff_idx entries qualify.
        from datetime import timedelta

        cutoff_dt = base_dt + timedelta(microseconds=cutoff_idx) - timedelta(microseconds=0)
        # The cutoff is "strictly before"; entry at index cutoff_idx
        # has ts == cutoff exactly, so it does NOT qualify.

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        archive_path = archive_dir / "archive-1.bin"

        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=cutoff_dt,
            output=archive_path,
        )
        assert result is not None
        assert result.compacted_count == cutoff_idx
        assert archive_path.exists()

        # Live log should now have: marker + retained entries.
        live = list(backend.iter_entries())
        assert len(live) == 1 + (N - cutoff_idx)
        assert is_compaction_marker(live[0])

        # Live-only verification: this is EXPECTED to fail because the
        # marker creates a fork that only verify_with_archives can
        # bridge. We just confirm the live walker finds breaks; we
        # don't constrain which kind, because either LINK_MISMATCH or
        # SELF_MISMATCH is acceptable depending on how the marker's
        # prev_hmac compares to the prior live entry's hmac.
        live_only = ChainVerifier(backend, keyring).verify()
        assert not live_only.ok

        # Full-chain verification with archives must be clean.
        report = verify_with_archives(
            backend=backend, keyring=keyring, archive_dir=archive_dir
        )
        assert report.ok, f"breaks: {report.breaks[:5]}"
        assert report.total_entries == N + 1  # +1 for the marker


class TestTamperDetection:
    def test_verify_with_archives_detects_merkle_tampering(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path, keyring: KeyRing
    ) -> None:
        """Flip a bit in an archived entry's reason. The Merkle root
        recomputation no longer matches the marker's claim → MERKLE_MISMATCH."""
        for i in range(5):
            chain.append(_make_entry(f"e{i}"))

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        archive_path = archive_dir / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive_path,
        )

        # Tamper: replace one entry's reason in the archived JSONL.
        # We do this by reading the archive, rewriting the entries,
        # and writing back. Easiest path: read raw bytes and patch
        # the gzip-compressed JSONL section.
        import gzip

        from signet.audit.compactor import (
            _ENTRIES_END,
            _ENTRIES_START,
        )

        raw = archive_path.read_bytes()
        es = raw.find(_ENTRIES_START) + len(_ENTRIES_START)
        ee = raw.find(_ENTRIES_END)
        gz_blob = raw[es:ee]
        jsonl = gzip.decompress(gz_blob).decode("utf-8")
        tampered_jsonl = jsonl.replace(
            '"reason":"e2"', '"reason":"e2-TAMPERED"', 1
        )
        # Re-gzip the tampered JSONL — but with the same deterministic
        # parameters used by the writer, so structurally it's a valid
        # archive. The Merkle root over the entries' .hmac fields is
        # still the same (we didn't touch hmac), so MERKLE_MISMATCH
        # is NOT what catches this — SELF_MISMATCH is. Let's instead
        # tamper with the hmac field directly to force MERKLE_MISMATCH.
        del tampered_jsonl
        tampered_jsonl = jsonl.replace(
            '"hmac":"', '"hmac":"0' * 0 + '"', 0  # no-op, we'll do something else
        )
        # Simpler: find the first occurrence of `"hmac":"X` and replace
        # the first hex digit with a different one.
        idx = jsonl.find('"hmac":"')
        # Move past the field name to the digest.
        digest_start = idx + len('"hmac":"')
        original_char = jsonl[digest_start]
        new_char = "0" if original_char != "0" else "1"
        tampered_jsonl = (
            jsonl[:digest_start] + new_char + jsonl[digest_start + 1 :]
        )

        from signet.audit.compactor import _gzip_bytes_deterministic

        new_gz = _gzip_bytes_deterministic(tampered_jsonl.encode("utf-8"))
        new_raw = raw[:es] + new_gz + raw[ee:]
        archive_path.write_bytes(new_raw)

        report = verify_with_archives(
            backend=backend, keyring=keyring, archive_dir=archive_dir
        )
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MERKLE_MISMATCH in kinds

    def test_verify_with_archives_detects_missing_archive(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path, keyring: KeyRing
    ) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        archive_path = archive_dir / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive_path,
        )
        archive_path.unlink()

        report = verify_with_archives(
            backend=backend, keyring=keyring, archive_dir=archive_dir
        )
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_MISSING in kinds

    def test_verify_with_archives_detects_format_invalid(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path, keyring: KeyRing
    ) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        archive_path = archive_dir / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive_path,
        )

        # Corrupt the magic prefix.
        raw = archive_path.read_bytes()
        archive_path.write_bytes(b"NOPE-NOT-AN-ARCHIVE\n" + raw[20:])

        report = verify_with_archives(
            backend=backend, keyring=keyring, archive_dir=archive_dir
        )
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds


class TestTrim:
    def test_trim_before_index(self, chain: HmacChain, backend: JsonlBackend) -> None:
        for i in range(5):
            chain.append(_make_entry(f"e{i}"))
        new_count = trim_before_index(backend, 2)
        assert new_count == 3
        remaining = list(backend.iter_entries())
        assert len(remaining) == 3
        assert remaining[0].reason == "e2"

    def test_trim_zero_is_noop(self, chain: HmacChain, backend: JsonlBackend) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))
        assert trim_before_index(backend, 0) == 3
        assert len(list(backend.iter_entries())) == 3

    def test_trim_negative_rejected(self, backend: JsonlBackend) -> None:
        with pytest.raises(ValueError):
            trim_before_index(backend, -1)


class TestCorruptArchiveBody:
    """A1 (v0.1.7): a corrupted gzip body in the archive's entries
    section must surface as a structured ARCHIVE_FORMAT_INVALID
    break, not a Python traceback."""

    def test_corrupt_gzip_blob_yields_archive_format_invalid(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path, keyring: KeyRing
    ) -> None:
        for i in range(5):
            chain.append(_make_entry(f"e{i}"))
        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        archive_path = archive_dir / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive_path,
        )

        from signet.audit.compactor import _ENTRIES_END, _ENTRIES_START

        raw = archive_path.read_bytes()
        es = raw.find(_ENTRIES_START) + len(_ENTRIES_START)
        ee = raw.find(_ENTRIES_END)
        # Corrupt one byte well into the gzip body so decompression
        # fails. Picking the middle of the blob avoids hitting the
        # gzip header which has its own validation path.
        midpoint = (es + ee) // 2
        bad = bytearray(raw)
        bad[midpoint] ^= 0xFF
        archive_path.write_bytes(bytes(bad))

        report = verify_with_archives(
            backend=backend, keyring=keyring, archive_dir=archive_dir
        )
        # Must not crash. Must report ARCHIVE_FORMAT_INVALID.
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds


class TestStackedCompactionRefusal:
    """A2 (v0.1.7): re-compacting over an existing compaction marker
    is refused with a clear ValueError pointing at the offending
    marker. Multi-archive bridge support is a Phase-2 item."""

    def test_compact_then_compact_again_refuses(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        # Append entries with old timestamps, compact half. The marker
        # itself is appended via HmacChain.append so its ts_ns is the
        # wall-clock at compaction time. Then run a second compaction
        # whose ``before`` cutoff is far in the future — the marker
        # qualifies, and the compactor must refuse.
        from datetime import timedelta

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(10):
            chain.append(
                _make_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000)
            )
        archive1 = tmp_path / "archive-1.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=base_dt + timedelta(seconds=5),
            output=archive1,
        )
        # Append more entries; their ts_ns is also "now" (real wall
        # clock), so a far-future cutoff for compact #2 sweeps in
        # marker + post-marker entries together.
        for i in range(5):
            chain.append(_make_entry(f"post-{i}"))

        archive2 = tmp_path / "archive-2.bin"
        with pytest.raises(ValueError, match="previous compaction marker"):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime(2099, 1, 1, tzinfo=UTC),
                output=archive2,
            )

    def test_idempotent_compact_with_same_cutoff_refuses(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        from datetime import timedelta

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(5):
            chain.append(
                _make_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000)
            )
        cutoff = base_dt + timedelta(seconds=3)
        archive1 = tmp_path / "archive-1.bin"
        compact_audit_log(
            chain=chain, backend=backend, before=cutoff, output=archive1
        )
        # Second invocation with same cutoff: the existing marker
        # has ts_ns at the time of the FIRST compaction (now), but the
        # remaining entries past the cutoff are still after it. The
        # marker itself was appended via HmacChain.append so its
        # ts_ns is "now" — strictly LATER than the cutoff window.
        # The truly-idempotent semantics is "no new entries are
        # eligible" → no-op, which is fine. Re-running with a
        # cutoff that includes the marker MUST refuse.
        far_future = datetime(2099, 1, 1, tzinfo=UTC)
        archive2 = tmp_path / "archive-2.bin"
        with pytest.raises(ValueError, match="previous compaction marker"):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=far_future,
                output=archive2,
            )


class TestRefuseOverwrite:
    """A4 (v0.1.7): compaction refuses to silently overwrite an
    existing archive at the output path; pass force=True to override."""

    def test_existing_output_path_refused(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))
        archive = tmp_path / "archive.bin"
        archive.write_bytes(b"some prior contents that must not be clobbered")

        with pytest.raises(FileExistsError, match="force=True"):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime(2099, 1, 1, tzinfo=UTC),
                output=archive,
            )
        # Sanity: the existing file is intact.
        assert archive.read_bytes().startswith(b"some prior contents")

    def test_force_true_overwrites(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))
        archive = tmp_path / "archive.bin"
        archive.write_bytes(b"prior contents to be replaced")

        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
            force=True,
        )
        assert result is not None
        # The archive is now a real archive, not the placeholder.
        assert archive.read_bytes().startswith(b"SIGNET-ARCHIVE-V")


class TestCompactionLockingHook:
    """A7 (v0.1.7): the compactor takes the same sidecar lock that
    FileLockingJsonlBackend appenders take, so concurrent appenders
    block on the lock instead of silently racing into the
    ``os.replace`` window."""

    def test_compactor_holds_sidecar_lock(
        self, tmp_path: Path
    ) -> None:
        from signet.audit.backend import (
            FileLockingJsonlBackend,
            exclusive_log_lock,
        )

        path = tmp_path / "audit.jsonl"
        backend = FileLockingJsonlBackend(path, fsync_after_append=False)
        ring = KeyRing(active=Key(key_id="k1", secret=b"x" * 32))
        chain = HmacChain(backend, ring, cache_prev=False)
        for i in range(3):
            chain.append(_make_entry(f"e{i}"))

        # The sidecar lockfile exists (compactor would touch it). We
        # take the lock from the test thread and confirm the appender
        # blocks (best-effort: we can't easily test cross-process
        # blocking with msvcrt.locking, but we can verify the
        # appender's path goes through exclusive_log_lock).
        # Smoke check: no exception when a compaction runs and an
        # appender follows.
        archive = tmp_path / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
        )
        # After compaction, the sidecar lockfile should exist.
        assert (tmp_path / "audit.jsonl.lock").exists()

        # And the lock context-manager works as a no-op when nobody
        # else holds it.
        with exclusive_log_lock(path):
            pass


class TestArchiveHeaderJson:
    def test_header_json_round_trip(self) -> None:
        h = ArchiveHeader(
            archive_format_version=1,
            signet_version="0.1.6",
            range_start="2026-01-01T00:00:00Z",
            range_end="2026-04-01T00:00:00Z",
            entry_count=42,
            merkle_root="ab" * 32,
        )
        line = h.to_json_line()
        restored = ArchiveHeader.from_json_line(line)
        assert restored == h


class TestCompactionResultShape:
    def test_result_fields_populated(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        for i in range(4):
            chain.append(_make_entry(f"e{i}"))
        archive = tmp_path / "archive.bin"
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=archive,
        )
        assert isinstance(result, CompactionResult)
        assert result.compacted_count == 4
        assert result.archive_path == archive.resolve()
        assert len(result.merkle_root) == 64
        assert len(result.range) == 2
        assert result.marker_entry_id
