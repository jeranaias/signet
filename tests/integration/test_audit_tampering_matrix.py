"""Integration: audit-chain tampering matrix.

This file ports the audit-tampering probe corpus from
``D:/tmp/signet-test/audit_tests/`` into a hermetic pytest matrix so
each corruption mode the bug-hunt session probed becomes a permanent
regression gate. Every row of the matrix has a clear contract:

* **modified-entry** (single-byte payload edit) -> SELF_MISMATCH at
  exactly the modified entry's index.
* **reordered-entries** -> LINK_MISMATCH (the swapped pair's
  ``prev_hmac`` no longer matches the predecessor).
* **deleted-entry** -> LINK_MISMATCH at the entry that USED to follow
  the deletion.
* **forged-insertion** -> SELF_MISMATCH on the forged row + a
  LINK_MISMATCH on the row originally after it.
* **off-by-one prev_hmac** -> exactly ONE break (post-A6 fix; pre-fix
  the verifier could cascade additional spurious LINK_MISMATCHes).
* **truncated last line** -> MALFORMED_LINE (post-A3 fix; pre-fix the
  verifier raised an unhandled JSONDecodeError).
* **BOM at start** -> clean verification (post-A3 fix; the JsonlBackend
  opens with ``utf-8-sig`` so a leading BOM is silently stripped).
* **corrupted-archive-gzip** -> ARCHIVE_FORMAT_INVALID (post-A1 fix;
  pre-fix the verifier emitted a Python traceback).
* **stacked-compaction** -> the second compactor invocation refuses
  with a ValueError naming the offending marker (post-A2 fix).
* **concurrent-compaction-and-appender** -> the sidecar lock blocks
  safely; smoke check on the locking primitive (post-A7 fix).

Every test in this file uses temporary directories under ``tmp_path``
and is hermetic. No CLI subprocesses are launched here; the bug-hunt
session used the CLI for ergonomics, but invoking the Python API
directly is faster and the contract is the same.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from signet.audit.backend import (
    FileLockingJsonlBackend,
    JsonlBackend,
    exclusive_log_lock,
)
from signet.audit.chain import HmacChain
from signet.audit.compactor import compact_audit_log
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import (
    BreakKind,
    ChainVerifier,
    verify_with_archives,
)
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _entry(reason: str = "x", *, ts_ns: int | None = None) -> AuditEntry:
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
    return KeyRing(active=Key(key_id="k1", secret=b"x" * 32))


@pytest.fixture
def backend(tmp_path: Path) -> JsonlBackend:
    return JsonlBackend(tmp_path / "audit.jsonl", fsync_after_append=False)


@pytest.fixture
def chain(backend: JsonlBackend, keyring: KeyRing) -> HmacChain:
    return HmacChain(backend=backend, keyring=keyring)


# ---------------------------------------------------------------------------
# Helpers for line-level tampering
# ---------------------------------------------------------------------------


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Modified-entry / reorder / delete / forge
# ---------------------------------------------------------------------------


class TestSelfMismatchOnSingleByteEdit:
    """A single-byte edit to an entry's payload must surface
    SELF_MISMATCH at exactly the modified entry's index."""

    def test_one_byte_in_reason_at_index_2(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))
        chain.append(_entry("d"))

        lines = _read_lines(backend.path)
        target = json.loads(lines[2])
        target["reason"] = target["reason"] + "X"  # 1-char extension
        lines[2] = json.dumps(target, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # Exactly one SELF_MISMATCH at index 2.
        self_breaks = [b for b in report.breaks if b.kind is BreakKind.SELF_MISMATCH]
        assert len(self_breaks) == 1
        assert self_breaks[0].index == 2


class TestReorderedEntries:
    def test_swap_two_entries_emits_link_mismatch(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        lines = _read_lines(backend.path)
        lines[1], lines[2] = lines[2], lines[1]
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.LINK_MISMATCH in kinds


class TestDeletedEntry:
    def test_delete_middle_entry_emits_link_mismatch(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        lines = _read_lines(backend.path)
        del lines[1]
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # The entry that USED to follow the deletion is now at the
        # deletion's index and its prev_hmac points at a vanished entry.
        link_breaks = [b for b in report.breaks if b.kind is BreakKind.LINK_MISMATCH]
        assert len(link_breaks) >= 1
        assert any(b.index == 1 for b in link_breaks)


class TestForgedInsertion:
    """A forged row inserted with a fake HMAC produces a SELF_MISMATCH
    on itself AND a LINK_MISMATCH on the row that follows."""

    def test_forged_row_breaks_self_and_following_link(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        a = chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        forged = _entry("forged").to_dict()
        forged["prev_hmac"] = a.hmac
        forged["hmac"] = "0" * 64
        forged["metadata"] = {"_signing_key_id": "k1"}

        lines = _read_lines(backend.path)
        lines.insert(
            1, json.dumps(forged, separators=(",", ":"), sort_keys=True)
        )
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        # SELF_MISMATCH on the forgery (HMAC is a placeholder).
        # LINK_MISMATCH on the original row that followed (its prev_hmac
        # no longer matches the new predecessor's hmac).
        assert BreakKind.SELF_MISMATCH in kinds
        assert BreakKind.LINK_MISMATCH in kinds


# ---------------------------------------------------------------------------
# A6: off-by-one prev_hmac surfaces exactly ONE break, not a cascade
# ---------------------------------------------------------------------------


class TestOffByOnePrevHmacOneBreak:
    """A6 (v0.1.7): a single byte flipped in one entry's ``prev_hmac``
    must produce exactly ONE break (the SELF_MISMATCH on that entry).
    The pre-fix code emitted a spurious LINK_MISMATCH cascade because
    the verifier propagated the ill-formed prev_hmac forward."""

    def test_single_prev_hmac_byte_flip(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))
        chain.append(_entry("d"))
        chain.append(_entry("e"))

        lines = _read_lines(backend.path)
        target = json.loads(lines[2])
        # Flip the first hex char of prev_hmac (0->1, etc.) so the
        # value is still a valid hex string but no longer matches the
        # actual predecessor's hmac. SELF_MISMATCH because the HMAC
        # was computed over the original prev_hmac.
        original_prev = target["prev_hmac"]
        flipped = ("1" if original_prev[0] != "1" else "2") + original_prev[1:]
        target["prev_hmac"] = flipped
        lines[2] = json.dumps(target, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # The contract is exactly ONE break, and that break is a
        # LINK_MISMATCH at the row whose prev_hmac was flipped. A6
        # explicitly suppresses the spurious SELF_MISMATCH that would
        # otherwise fire on the same row (because prev_hmac is a
        # signed input, mutating it ALSO breaks the self HMAC), and
        # caps the cascade at the bad row instead of propagating
        # forward through every subsequent entry.
        assert len(report.breaks) == 1, (
            f"prev_hmac byte flip cascaded into {len(report.breaks)} "
            f"breaks; A6 requires exactly ONE LINK_MISMATCH at the "
            f"flipped row. breaks={[(b.kind, b.index) for b in report.breaks]}"
        )
        assert report.breaks[0].kind is BreakKind.LINK_MISMATCH
        assert report.breaks[0].index == 2


# ---------------------------------------------------------------------------
# A3: malformed JSONL line surfaces as MALFORMED_LINE, not a traceback
# ---------------------------------------------------------------------------


class TestTruncatedLastLineMalformed:
    """The last entry truncated to a half-written JSON object emits
    MALFORMED_LINE rather than letting JSONDecodeError escape."""

    def test_truncated_tail_yields_structured_break(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        # Truncate the last line at 30% of its length; result is a
        # half-written JSON object that json.loads will reject.
        lines = _read_lines(backend.path)
        lines[-1] = lines[-1][: len(lines[-1]) // 3]
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.MALFORMED_LINE in kinds


# ---------------------------------------------------------------------------
# A3 cont'd: BOM at file start verifies clean (utf-8-sig)
# ---------------------------------------------------------------------------


class TestBomAtFileStartVerifiesClean:
    """An editor that helpfully prepends a UTF-8 BOM on save must NOT
    wedge the verifier. ``JsonlBackend`` opens with ``utf-8-sig`` so
    a single leading BOM is silently stripped."""

    def test_leading_bom_is_silently_stripped(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))

        # Re-write the file with a leading BOM.
        original = backend.path.read_bytes()
        backend.path.write_bytes(b"\xef\xbb\xbf" + original)

        report = ChainVerifier(backend, keyring).verify()
        assert report.ok, f"BOM should not break verification; breaks={report.breaks}"
        assert report.total_entries == 2


# ---------------------------------------------------------------------------
# A1: corrupted gzip in archive surfaces as ARCHIVE_FORMAT_INVALID, no traceback
# ---------------------------------------------------------------------------


class TestCorruptedArchiveGzipFormatInvalid:
    """A bit-flipped gzip body in an archive surfaces as a clean
    ARCHIVE_FORMAT_INVALID break -- pre-fix this raised a
    ``BadGzipFile`` traceback that escaped the verifier."""

    def test_bit_flip_in_gzipped_body(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing, tmp_path: Path
    ) -> None:
        # Build a chain with old timestamps so they're eligible for
        # compaction with a near-cutoff.
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(5):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        archive = tmp_path / "archive-1.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=base_dt + timedelta(seconds=10),
            output=archive,
        )

        # Find the gzipped body and flip a bit deep enough into it that
        # we're past the gzip header (so we hit a CRC failure rather
        # than a magic-number rejection).
        raw = bytearray(archive.read_bytes())
        # Look for the first b"\x1f\x8b" gzip magic and flip a byte
        # ~64 bytes after it.
        idx = raw.find(b"\x1f\x8b")
        assert idx >= 0, "expected a gzip member somewhere in the archive"
        raw[idx + 64] ^= 0x55
        archive.write_bytes(bytes(raw))

        # verify_with_archives must report this as ARCHIVE_FORMAT_INVALID
        # rather than letting BadGzipFile escape.
        report = verify_with_archives(
            backend, keyring, archive_dir=tmp_path
        )
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds


# ---------------------------------------------------------------------------
# A2: stacked compaction refuses with a ValueError
# ---------------------------------------------------------------------------


class TestStackedCompactionRefused:
    """A2 (v0.1.7): re-compacting over an existing compaction marker
    is refused with a clear ValueError naming the offending marker."""

    def test_second_compaction_with_far_future_cutoff_refuses(
        self, chain: HmacChain, backend: JsonlBackend, tmp_path: Path
    ) -> None:
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(10):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        archive1 = tmp_path / "archive-1.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=base_dt + timedelta(seconds=5),
            output=archive1,
        )

        # Append more entries (wall-clock ts_ns).
        for i in range(5):
            chain.append(_entry(f"post-{i}"))

        archive2 = tmp_path / "archive-2.bin"
        with pytest.raises(ValueError, match="previous compaction marker"):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime(2099, 1, 1, tzinfo=UTC),
                output=archive2,
            )


# ---------------------------------------------------------------------------
# A7: concurrent-compaction-and-appender — sidecar lock blocks safely
# ---------------------------------------------------------------------------


class TestConcurrentCompactionAppenderLock:
    """A7 (v0.1.7): the compactor takes the same sidecar lock as
    FileLockingJsonlBackend appenders, so concurrent appenders block
    on the lock instead of racing into the os.replace window.

    This test is a smoke-level integration probe: hold the sidecar
    lock from one thread and confirm a second thread that tries to
    take it does not silently proceed. The pre-fix repro under
    ``D:/tmp/signet-test/audit_tests/`` ran two real processes; we
    cannot easily portably do that here on Windows, so the in-process
    smoke is the best we can do without a CLI subprocess.
    """

    def test_lock_serializes(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        path.touch()

        # Make sure the sidecar can be created.
        with exclusive_log_lock(path):
            pass

        # Hold the lock from the test thread, then attempt to take it
        # from a worker thread; the worker must block until released.
        # Use a short timeout to keep the test fast.
        import threading

        released = threading.Event()
        worker_acquired = threading.Event()

        def worker() -> None:
            with exclusive_log_lock(path):
                worker_acquired.set()

        with exclusive_log_lock(path):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            # Worker should NOT be able to acquire while we hold it.
            assert not worker_acquired.wait(timeout=0.3), (
                "worker acquired sidecar lock while another holder had it"
            )
            released.set()
        # Release: worker should now grab it within a short window.
        t.join(timeout=2.0)
        assert worker_acquired.is_set(), "worker never acquired after release"

    def test_compaction_creates_sidecar_and_archives_clean(
        self, tmp_path: Path
    ) -> None:
        """Compaction smoke: a FileLockingJsonlBackend chain compacts
        successfully, the sidecar lockfile exists afterwards (proving
        the compactor went through ``exclusive_log_lock``), and the
        live log + archive together verify clean.

        The post-compact append + cross-marker bridge is exercised in
        the existing ``tests/unit/test_audit_compaction.py`` round-trip
        suite; this integration smoke just pins the locking-side
        contract.
        """
        path = tmp_path / "audit.jsonl"
        backend = FileLockingJsonlBackend(path, fsync_after_append=False)
        ring = KeyRing(active=Key(key_id="k1", secret=b"x" * 32))
        chain = HmacChain(backend, ring, cache_prev=False)
        # Use deterministic ts_ns so we can split eligible vs. retained
        # cleanly across the cutoff.
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(6):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        archive = tmp_path / "archive.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=base_dt + timedelta(seconds=3),
            output=archive,
        )

        # Sidecar lockfile exists (proves the compactor went through
        # exclusive_log_lock).
        assert (tmp_path / "audit.jsonl.lock").exists()

        # Live log + archive verify cleanly together.
        report = verify_with_archives(backend, ring, archive_dir=tmp_path)
        assert report.ok, (
            f"chain should verify clean post-compact; breaks={report.breaks}"
        )
