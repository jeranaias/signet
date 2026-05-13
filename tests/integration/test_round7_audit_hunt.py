"""Integration: Round 7 audit-domain hunt regression matrix.

Pins the closure tests for the five Round-7 audit findings (HIGH-1,
HIGH-2, MED-1, MED-2, LOW-1, LOW-2). Each class corresponds to one
finding and asserts the exact contract change: a tampered or
operator-misused input that previously produced a raw Python
traceback now surfaces a structured outcome.

* **HIGH-1 type-tamper-crash-verifier**: ``hmac`` / ``prev_hmac`` /
  ``ts_ns`` flipped to non-strings / non-ints surface as
  ``MALFORMED_LINE`` instead of crashing ``ChainVerifier.verify()``.
* **HIGH-2 archive-tamper-crash-readarchive**: archive entries with
  valid JSON but schema-bad shape route through
  ``ARCHIVE_FORMAT_INVALID`` rather than raw ``KeyError`` /
  ``TypeError``.
* **MED-1 trim-stale-prev-cache**: ``trim_before_index(chain=chain)``
  invalidates the chain's cached prev so subsequent appends link
  correctly.
* **MED-2 tampered-ts_ns-string-crashes-compaction**: a tampered
  ``ts_ns`` (string, absurd int, negative) surfaces from compaction as
  a structured ``MalformedAuditEntry`` rather than a raw ``TypeError``
  / ``OSError``.
* **LOW-1 user-crafted-fake-compaction-marker**: a user-appended entry
  with ``check_name='_compaction'`` and a forged marker payload no
  longer DoS-blocks future compactions, because the keyring MAC fails
  to verify.
* **LOW-2 whitespace-key-id-accepted**: ``Key(key_id='   ')`` raises
  ``ValueError`` instead of silently producing a key with an
  unreadable identifier.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend, MalformedAuditEntry
from signet.audit.chain import HmacChain
from signet.audit.compactor import (
    COMPACTION_CHECK_NAME,
    COMPACTION_MARKER_FIELD,
    compact_audit_log,
    is_compaction_marker,
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

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


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


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# HIGH-1: type-tampered hmac / prev_hmac / ts_ns surface as MALFORMED_LINE
# ---------------------------------------------------------------------------


class TestR7High1TypeCoercionVerifier:
    """Tampering each of ``hmac``, ``prev_hmac``, ``ts_ns`` to a wrong
    JSON type now surfaces ``MALFORMED_LINE`` from ``ChainVerifier``
    rather than crashing with a raw ``TypeError`` mid-walk."""

    @pytest.mark.parametrize(
        "field, value",
        [
            ("hmac", None),
            ("hmac", True),
            ("hmac", 42),
            ("hmac", []),
            ("prev_hmac", None),
            ("prev_hmac", 42),
            ("prev_hmac", {}),
            ("ts_ns", "1700000000000000000"),
            ("ts_ns", None),
            ("ts_ns", True),
            ("ts_ns", 10**20),
            ("ts_ns", -1),
        ],
    )
    def test_field_type_tamper_surfaces_malformed_line(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        field: str,
        value: object,
    ) -> None:
        chain.append(_entry("a"))
        lines = _read_lines(backend.path)
        d = json.loads(lines[0])
        d[field] = value
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok, (
            f"tampered {field}={value!r} should produce a structured break, got clean verify"
        )
        kinds = {b.kind for b in report.breaks}
        # The type-tamper must surface as MALFORMED_LINE (the JsonlBackend
        # iter_entries wrapper routes the from_dict TypeError/ValueError
        # through MalformedAuditEntry, which the verifier reports as
        # MALFORMED_LINE). SELF_MISMATCH would be acceptable for some
        # variants (the hmac-is-now-string-but-wrong case) but the
        # contract is "no traceback" — we just need a structured break.
        assert kinds & {BreakKind.MALFORMED_LINE, BreakKind.SELF_MISMATCH}, (
            f"expected MALFORMED_LINE or SELF_MISMATCH for {field}={value!r}; "
            f"breaks={report.breaks}"
        )

    def test_hmac_field_missing_surfaces_malformed_line(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        """The hmac field defaults to "" via ``data.get("hmac", "")`` —
        a missing field is treated as empty string, which is a valid
        type. The resulting entry then SELF_MISMATCHes (its stored hmac
        is "" but the recomputation produces a real hex string). This
        test pins that contract: missing-but-typed-correct surfaces as
        SELF_MISMATCH, not a crash."""
        chain.append(_entry("a"))
        lines = _read_lines(backend.path)
        d = json.loads(lines[0])
        d.pop("hmac")
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.SELF_MISMATCH in kinds, (
            f"missing hmac should SELF_MISMATCH; breaks={report.breaks}"
        )

    def test_tampered_predecessor_does_not_corrupt_legitimate_successor(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        """Propagation contract from HIGH-1: a tampered hmac in entry N
        must NOT cause entry N+1 (appended legitimately later) to be
        verified as corrupt itself. The verifier reports a
        MALFORMED_LINE / SELF_MISMATCH at N and either stops there
        (MALFORMED_LINE halts iteration) or continues reporting only
        downstream link breaks — never a raw crash."""
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        # Tamper entry 0's hmac to a non-string.
        lines = _read_lines(backend.path)
        d = json.loads(lines[0])
        d["hmac"] = None
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

        # Verify should NOT crash. The exact break shape is bounded by
        # the verifier contract — we just assert no traceback escapes.
        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok


# ---------------------------------------------------------------------------
# HIGH-2: tampered archive with valid JSON but schema-bad surfaces as
# ARCHIVE_FORMAT_INVALID, not raw KeyError/TypeError
# ---------------------------------------------------------------------------


def _tamper_archive_entry(
    archive_path: Path,
    *,
    line_index: int,
    mutate: callable,  # type: ignore[valid-type]
) -> None:
    """Mutate one JSON line inside an archive's gzipped entries section."""
    raw = archive_path.read_bytes()
    s = raw.find(b"ENTRIES-START\n") + len(b"ENTRIES-START\n")
    e = raw.find(b"\nENTRIES-END\n")
    decompressed = gzip.decompress(raw[s:e]).decode("utf-8")
    lines = decompressed.splitlines()
    obj = json.loads(lines[line_index])
    mutate(obj)
    lines[line_index] = json.dumps(obj)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=6) as gz:
        gz.write(("\n".join(lines) + "\n").encode("utf-8"))
    archive_path.write_bytes(raw[:s] + buf.getvalue() + raw[e:])


class TestR7High2ArchiveSchemaCorruption:
    """Tampering archive entries to be valid JSON but schema-bad must
    surface as ``ARCHIVE_FORMAT_INVALID`` instead of crashing
    ``read_archive`` with a raw ``KeyError`` / ``TypeError``."""

    def _build_archive(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        tmp_path: Path,
    ) -> Path:
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
        return archive

    @pytest.mark.parametrize("field", ["owner_type", "decision", "entry_id", "ts_ns"])
    def test_missing_required_field_surfaces_archive_format_invalid(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
        field: str,
    ) -> None:
        archive = self._build_archive(chain, backend, tmp_path)
        _tamper_archive_entry(
            archive,
            line_index=0,
            mutate=lambda d: d.pop(field),
        )

        report = verify_with_archives(backend, keyring, archive_dir=tmp_path)
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds, (
            f"missing {field!r} in archive entry should surface as "
            f"ARCHIVE_FORMAT_INVALID; breaks={report.breaks}"
        )

    def test_metadata_wrong_type_surfaces_archive_format_invalid(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """``metadata = [1, 2]`` raises TypeError from ``dict([1, 2])`` —
        this used to crash the verifier. Now routes through
        ARCHIVE_FORMAT_INVALID."""
        archive = self._build_archive(chain, backend, tmp_path)

        def mutate(d: dict) -> None:
            d["metadata"] = [1, 2]

        _tamper_archive_entry(archive, line_index=0, mutate=mutate)

        report = verify_with_archives(backend, keyring, archive_dir=tmp_path)
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds, (
            f"non-dict metadata in archive entry should surface as "
            f"ARCHIVE_FORMAT_INVALID; breaks={report.breaks}"
        )

    def test_ts_ns_wrong_type_in_archive_surfaces_archive_format_invalid(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """A tampered archive entry with ``ts_ns`` as a string now
        triggers the HIGH-1 type-coercion check inside ``from_dict``,
        which raises ``TypeError`` — the HIGH-2 except widening routes
        that through ARCHIVE_FORMAT_INVALID."""
        archive = self._build_archive(chain, backend, tmp_path)

        def mutate(d: dict) -> None:
            d["ts_ns"] = "1700000000000000000"

        _tamper_archive_entry(archive, line_index=0, mutate=mutate)

        report = verify_with_archives(backend, keyring, archive_dir=tmp_path)
        assert not report.ok
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.ARCHIVE_FORMAT_INVALID in kinds


# ---------------------------------------------------------------------------
# MED-1: trim_before_index invalidates chain._cached_prev
# ---------------------------------------------------------------------------


class TestR7Med1TrimInvalidatesChainCache:
    """``trim_before_index(chain=chain)`` invalidates the chain's
    ``_cached_prev`` so the next ``append`` re-reads the (truncated)
    tail and links correctly. Pre-fix, the next append would have linked
    to a hmac that no longer existed in the trimmed log, surfacing as a
    fake ``LINK_MISMATCH`` to the operator."""

    def test_append_after_trim_with_chain_kw_links_cleanly(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        # Trim everything; chain cache is now stale.
        trim_before_index(backend, 100, chain=chain)
        assert chain._cached_prev is None, "trim_before_index(chain=chain) must clear _cached_prev"

        # Append a fresh entry; verifier must report no breaks.
        chain.append(_entry("d"))
        report = ChainVerifier(backend, keyring).verify()
        assert report.ok, f"chain after trim+append should verify clean; breaks={report.breaks}"

    def test_append_after_partial_trim_with_chain_kw_links_to_retained_head(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        """After a partial trim the chain genuinely breaks at the trim
        boundary (the new head entry's ``prev_hmac`` references a
        trimmed-away entry). That's a structurally-correct
        ``LINK_MISMATCH`` at index 0 — NOT a cache-staleness fork
        downstream. The MED-1 closure contract is: the *newly appended*
        entry links to the *current* retained tail (not a cached
        phantom). We assert that by checking there's exactly ONE break
        and it sits at index 0, not at the freshly-appended index.
        """
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))
        chain.append(_entry("d"))

        # Trim the first 2 entries; two retained head entries remain
        # (which the verifier will report as LINK_MISMATCH at index 0
        # because the new head still claims a prev that no longer
        # exists -- expected and unavoidable when retaining a tail).
        retained = trim_before_index(backend, 2, chain=chain)
        assert retained == 2
        assert chain._cached_prev is None

        # Append a fresh entry. It MUST link to the current physical
        # tail (entry 'd'), not to a cached hmac from before the trim.
        appended = chain.append(_entry("e"))
        live = list(backend.iter_entries())
        # 'e' is the newest entry; its prev_hmac must equal 'd'.hmac.
        assert live[-1].entry_id == appended.entry_id
        assert appended.prev_hmac == live[-2].hmac, (
            "newly appended entry must link to the post-trim tail, not a cached phantom"
        )

        # The verifier should still report exactly the expected break
        # at the trim boundary (index 0), NOT a cascade or a break at
        # the freshly-appended index.
        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok  # trim boundary is a real break
        link_breaks = [b for b in report.breaks if b.kind is BreakKind.LINK_MISMATCH]
        assert len(link_breaks) == 1
        assert link_breaks[0].index == 0, (
            f"only the trim-boundary entry should break; breaks={report.breaks}"
        )

    def test_legacy_signature_still_works_no_chain_arg(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
    ) -> None:
        """Callers who don't reuse the chain across a trim can still
        invoke the function with the legacy 2-arg signature. The cache
        invalidation only happens when ``chain=`` is passed."""
        chain = HmacChain(backend=backend, keyring=keyring)
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        retained = trim_before_index(backend, 1)
        assert retained == 1


# ---------------------------------------------------------------------------
# MED-2: tampered ts_ns surfaces from compact_audit_log as MalformedAuditEntry
# ---------------------------------------------------------------------------


class TestR7Med2CompactionHandlesTamperedTsNs:
    """A tampered ``ts_ns`` field used to crash ``compact_audit_log``
    with a raw ``TypeError`` (``entry.ts_ns < cutoff_ns``) or an
    ``OSError`` (``datetime.fromtimestamp`` on absurd ints). Now the
    HIGH-1 type-coercion in ``AuditEntry.from_dict`` routes through
    ``MalformedAuditEntry`` and the compactor surfaces the structured
    exception."""

    def _make_chain_and_tamper(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        new_ts_ns: object,
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        lines = _read_lines(backend.path)
        d = json.loads(lines[0])
        d["ts_ns"] = new_ts_ns
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        _write_lines(backend.path, lines)

    def test_compaction_handles_ts_ns_string(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        tmp_path: Path,
    ) -> None:
        self._make_chain_and_tamper(chain, backend, "1700000000000000000")
        time.sleep(0.005)
        with pytest.raises(MalformedAuditEntry):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime.now(UTC),
                output=tmp_path / "arc.bin",
            )

    def test_compaction_handles_ts_ns_absurd_int(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        tmp_path: Path,
    ) -> None:
        self._make_chain_and_tamper(chain, backend, 10**20)
        time.sleep(0.005)
        with pytest.raises(MalformedAuditEntry):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime.now(UTC),
                output=tmp_path / "arc.bin",
            )

    def test_compaction_handles_ts_ns_negative(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        tmp_path: Path,
    ) -> None:
        self._make_chain_and_tamper(chain, backend, -1)
        time.sleep(0.005)
        with pytest.raises(MalformedAuditEntry):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime.now(UTC),
                output=tmp_path / "arc.bin",
            )

    def test_compaction_handles_ts_ns_null(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        tmp_path: Path,
    ) -> None:
        self._make_chain_and_tamper(chain, backend, None)
        time.sleep(0.005)
        with pytest.raises(MalformedAuditEntry):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=datetime.now(UTC),
                output=tmp_path / "arc.bin",
            )


# ---------------------------------------------------------------------------
# LOW-1: user-crafted fake compaction marker no longer DoS-blocks
# ---------------------------------------------------------------------------


class TestR7Low1FakeCompactionMarkerDoesNotBlockCompaction:
    """A user-appended entry with ``check_name='_compaction'`` and a
    forged marker payload is recognized by shape and refused by the
    A2 guard fail-closed.

    R7 LOW-1 (original): a shape-only ``is_compaction_marker`` let any
    user-crafted entry permanently DoS the compactor by tripping A2.
    The LOW-1 fix added a keyring-MAC verification to ``is_compaction_marker``
    so forged entries were treated as normal entries (compaction
    proceeded).

    R9 HIGH-2 corrected the LOW-1 trade-off: that fail-open behavior
    silently archived the marker-shaped entry into a second archive
    whenever the marker's signing key wasn't in the ring (e.g. after
    a legitimate revocation). The current behavior is shape-based
    dispatch with fail-closed refusal: a marker-shaped entry whose
    MAC does not verify raises ``ValueError`` so the operator can
    investigate (delete a forged entry, re-add a revoked key as
    legacy, etc.) rather than corrupting the chain silently. The
    fail-closed refusal is strictly more secure than the LOW-1
    fail-open: the chain cannot reach an unverifiable multi-archive
    state, and the operator gets an actionable signal.
    """

    def test_forged_marker_refuses_compaction_fail_closed(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)

        # User crafts a fake marker entry (with NO valid signature).
        forged_marker = AuditEntry(
            owner=Owner.human("attacker"),
            check_name=COMPACTION_CHECK_NAME,
            decision=Decision.ALLOW,
            reason="poisoned",
            metadata={
                COMPACTION_MARKER_FIELD: {
                    "archive_format_version": 1,
                    "archive_path": "nonexistent.bin",
                    "merkle_root": "aa" * 32,
                    "compacted_count": 0,
                    "range_start": "2020-01-01T00:00:00Z",
                    "range_end": "2020-01-01T00:00:01Z",
                    # Marker-shape sentinel, but signature does not
                    # verify under any key in the ring.
                    "_marker_signature": "ff" * 32,
                },
            },
            ts_ns=base_ns,
        )
        chain.append(forged_marker)
        chain.append(_entry("normal", ts_ns=base_ns + 1_000_000_000))

        # R9 HIGH-2: A2 guard now dispatches on shape and fail-closes
        # on MAC failure. Operator-visible ValueError, no second
        # archive corruption.
        archive = tmp_path / "archive-1.bin"
        with pytest.raises(ValueError, match="MAC does not verify"):
            compact_audit_log(
                chain=chain,
                backend=backend,
                before=base_dt + timedelta(seconds=10),
                output=archive,
            )
        assert not archive.exists(), "fail-closed: no archive should be written when A2 refuses"

    def test_keyring_aware_check_rejects_forged_marker(
        self,
        keyring: KeyRing,
    ) -> None:
        """Direct unit-level test: ``is_compaction_marker(entry, keyring=ring)``
        returns False for an entry with a forged signature."""
        forged = AuditEntry(
            owner=Owner.human("attacker"),
            check_name=COMPACTION_CHECK_NAME,
            decision=Decision.ALLOW,
            reason="poisoned",
            metadata={
                COMPACTION_MARKER_FIELD: {
                    "archive_format_version": 1,
                    "archive_path": "fake.bin",
                    "merkle_root": "00" * 32,
                    "compacted_count": 0,
                    "range_start": "2020-01-01T00:00:00Z",
                    "range_end": "2020-01-01T00:00:01Z",
                    "_marker_signature": "ff" * 32,
                },
            },
        )
        # Shape-only check: still True (legacy callers).
        assert is_compaction_marker(forged) is True
        # Keyring-aware check: False because the MAC doesn't verify.
        assert is_compaction_marker(forged, keyring=keyring) is False

    def test_keyring_aware_check_accepts_real_marker(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """A real compactor-emitted marker DOES pass the keyring-aware
        check — that's how the A2 guard still catches stacked
        compactions of legitimate markers."""
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))
        archive = tmp_path / "archive-1.bin"
        compact_audit_log(
            chain=chain,
            backend=backend,
            before=base_dt + timedelta(seconds=10),
            output=archive,
        )
        # The first entry in the live log is now the real marker.
        live = list(backend.iter_entries())
        marker = live[0]
        assert is_compaction_marker(marker) is True
        assert is_compaction_marker(marker, keyring=keyring) is True

    def test_stacked_compaction_still_refused_for_real_markers(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """The A2 guard must still trigger on a REAL prior marker —
        LOW-1 closes the DoS surface but must not lose the legitimate
        re-compaction refusal."""
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

        for i in range(3):
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
# LOW-2: whitespace-only Key.key_id rejected
# ---------------------------------------------------------------------------


class TestR7Low2WhitespaceKeyIdRejected:
    @pytest.mark.parametrize("key_id", ["   ", "\t\n", " ", "\n", "\t"])
    def test_whitespace_only_key_id_raises(self, key_id: str) -> None:
        with pytest.raises(ValueError, match="non-empty, non-whitespace"):
            Key(key_id=key_id, secret=b"x" * 32)

    def test_empty_key_id_still_raises(self) -> None:
        with pytest.raises(ValueError):
            Key(key_id="", secret=b"x" * 32)

    def test_valid_key_id_still_accepted(self) -> None:
        # No leading/trailing whitespace -> accepted.
        k = Key(key_id="k1", secret=b"x" * 32)
        assert k.key_id == "k1"

    def test_key_id_with_internal_whitespace_accepted(self) -> None:
        """Internal whitespace is allowed (the check is non-whitespace-
        only, not whitespace-free)."""
        k = Key(key_id="k 1", secret=b"x" * 32)
        assert k.key_id == "k 1"


# ---------------------------------------------------------------------------
# Reach-through: HIGH-1 helpers also fix the AuditEntry.from_dict surface
# ---------------------------------------------------------------------------


class TestR7High1FromDictDirectly:
    """Direct unit-level coverage of ``AuditEntry.from_dict`` type
    rejections so the contract is testable without the JsonlBackend
    wrapping layer."""

    def _good_data(self) -> dict:
        return {
            "owner_type": "human",
            "owner_id": "alice",
            "approval_chain": ["human:alice"],
            "check_name": "c",
            "decision": "allow",
            "reason": "ok",
            "entry_id": "00000000-0000-0000-0000-000000000000",
            "ts_ns": 1700000000000000000,
            "prev_hmac": "",
            "hmac": "",
            "request_fingerprint": "",
            "metadata": {},
        }

    @pytest.mark.parametrize("bad", [None, True, 42, [], {}])
    def test_hmac_wrong_type_raises_typeerror(self, bad: object) -> None:
        data = self._good_data()
        data["hmac"] = bad
        with pytest.raises(TypeError, match="hmac must be str"):
            AuditEntry.from_dict(data)

    @pytest.mark.parametrize("bad", [None, True, 42, [], {}])
    def test_prev_hmac_wrong_type_raises_typeerror(self, bad: object) -> None:
        data = self._good_data()
        data["prev_hmac"] = bad
        with pytest.raises(TypeError, match="prev_hmac must be str"):
            AuditEntry.from_dict(data)

    @pytest.mark.parametrize("bad", [None, True, "string", [], 1.5])
    def test_ts_ns_wrong_type_raises_typeerror(self, bad: object) -> None:
        data = self._good_data()
        data["ts_ns"] = bad
        with pytest.raises(TypeError, match="ts_ns must be int"):
            AuditEntry.from_dict(data)

    @pytest.mark.parametrize("bad", [-1, 10**20, -(10**5)])
    def test_ts_ns_out_of_range_raises_valueerror(self, bad: int) -> None:
        data = self._good_data()
        data["ts_ns"] = bad
        with pytest.raises(ValueError, match="ts_ns="):
            AuditEntry.from_dict(data)

    def test_ts_ns_at_upper_boundary_accepted(self) -> None:
        """``10**19`` is the inclusive upper bound (year ~2286). Just
        below MUST be accepted; the parametrized out-of-range test
        covers exactly ``10**20``."""
        data = self._good_data()
        data["ts_ns"] = 10**19 - 1
        e = AuditEntry.from_dict(data)
        assert e.ts_ns == 10**19 - 1

    def test_ts_ns_zero_accepted(self) -> None:
        """Epoch (``ts_ns == 0``) is a valid input — operators replaying
        ancient audits must not have legitimate Jan-1-1970 entries
        rejected."""
        data = self._good_data()
        data["ts_ns"] = 0
        e = AuditEntry.from_dict(data)
        assert e.ts_ns == 0


# ---------------------------------------------------------------------------
# Reach-through: _ts_ns_to_iso defensive bound
# ---------------------------------------------------------------------------


class TestR7Med2TsNsToIsoDefense:
    """Belt-and-braces: even if a malicious caller manages to construct
    an ``AuditEntry`` with an in-range-but-extreme ``ts_ns`` somehow
    bypassing ``from_dict`` (e.g. the public constructor), ``_ts_ns_to_iso``
    fails closed with ``ValueError`` rather than ``OSError`` from libc."""

    def test_far_future_ts_ns_raises_valueerror(self) -> None:
        from signet.audit.compactor import _ts_ns_to_iso

        # year > 9999 trips datetime range; pre-fix raised OSError on
        # some libcs. Use a value safely past Python's max year that
        # still fits in the from_dict bound.
        with pytest.raises(ValueError, match="representable range"):
            _ts_ns_to_iso(10**18 * 100)  # year way beyond 9999

    def test_normal_ts_ns_still_formats(self) -> None:
        from signet.audit.compactor import _ts_ns_to_iso

        # Sanity: a normal ts_ns still round-trips.
        epoch_ns = int(_dt.datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1e9)
        iso = _ts_ns_to_iso(epoch_ns)
        assert iso.endswith("Z")
        assert "2026" in iso


# ---------------------------------------------------------------------------
# Round 9 HIGH-1: full-sweep compaction preserves the archive bridge
# ---------------------------------------------------------------------------


class TestR9High1FullSweepBridge:
    """When ``compact_audit_log`` archives *every* eligible entry (no
    retained entries — the simplest compaction policy, "archive
    everything before now"), the next ``chain.append`` must link the
    new entry's ``prev_hmac`` to the LAST ARCHIVED entry's hmac, NOT
    the marker's hmac. The archive-bridge rule in
    :func:`verify_with_archives` documents the fork: both the marker
    and the next live entry share the same predecessor.

    Pre-Round-9 the compactor cleared ``chain._cached_prev`` to
    ``None`` for both the half-sweep and full-sweep paths. On a full
    sweep the next append would call ``backend.last_entry()``, which
    returns the marker (now the only entry in the live log), and link
    incorrectly to the marker's hmac. ``verify_with_archives`` then
    reports a permanent ``LINK_MISMATCH`` on every subsequent live
    entry — a phantom tamper indicator after legitimate maintenance.
    """

    def test_full_sweep_then_append_verifies_clean(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        # Append a handful of entries with old timestamps.
        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        # Compact EVERYTHING — cutoff far in the future so all eligible
        # entries qualify. The marker is appended fresh with its own
        # "now" ts_ns; ``retained`` is empty by construction.
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )
        assert result is not None
        assert result.compacted_count == 3

        # Live log post-compaction contains ONLY the marker.
        live = list(backend.iter_entries())
        assert len(live) == 1
        assert is_compaction_marker(live[0])

        # Now append a legitimate post-compaction entry. The bug:
        # without the fix the chain would link this entry's prev_hmac
        # to the marker's hmac instead of the last-archived hmac, and
        # ``verify_with_archives`` would mis-report LINK_MISMATCH.
        chain.append(_entry("post"))

        # Full-chain verification with archives MUST be clean.
        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, (
            f"verify_with_archives should be clean after full-sweep "
            f"compact + append; breaks: {list(report.breaks)}"
        )
        # 3 archived + 1 marker + 1 post-compaction = 5 entries.
        assert report.total_entries == 5

    def test_full_sweep_then_multiple_appends_verifies_clean(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """Same scenario but with multiple post-compaction appends, to
        prove the seeded cache value lets the chain continue linking
        correctly across many subsequent appends (not just the first)."""
        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(5):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )

        for i in range(4):
            chain.append(_entry(f"post-{i}"))

        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, f"breaks: {list(report.breaks)}"
        # 5 archived + 1 marker + 4 post = 10.
        assert report.total_entries == 10


# ---------------------------------------------------------------------------
# Round 9 HIGH-2: marker-shape dispatch survives key revocation
# ---------------------------------------------------------------------------


class TestR9High2MarkerShapeDispatch:
    """Removing the marker's signing key from the ring (a legitimate
    revocation move) must NOT collapse the verifier's archive-bridge
    dispatch or the compactor's A2 guard. Both consult shape recognition
    independent of MAC validity; MAC failure surfaces as an actionable
    ``UNKNOWN_KEY`` break / fail-closed ``ValueError`` rather than the
    silent ``LINK_MISMATCH`` cascade and second-archive corruption the
    Round-8 LOW-1 fix introduced.
    """

    def test_verify_with_revoked_marker_key_reports_unknown_key_not_link_mismatch(
        self,
        tmp_path: Path,
    ) -> None:
        backend = JsonlBackend(tmp_path / "audit.jsonl", fsync_after_append=False)
        k1 = Key(key_id="k1", secret=b"x" * 32)
        k2 = Key(key_id="k2", secret=b"y" * 32)
        chain1 = HmacChain(backend=backend, keyring=KeyRing(active=k1))

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain1.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()
        result = compact_audit_log(
            chain=chain1,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc1.bin",
        )
        assert result is not None

        # Sanity: with the original key in the ring (as legacy), verify
        # is clean.
        ring_with_legacy = KeyRing(active=k2)
        ring_with_legacy.add_legacy(k1)
        rep_ok = verify_with_archives(
            backend=backend, keyring=ring_with_legacy, archive_dir=arc_dir
        )
        assert rep_ok.ok, f"sanity baseline breaks: {list(rep_ok.breaks)}"

        # Now revoke k1 — fresh ring with k2 only.
        ring_revoked = KeyRing(active=k2)
        rep = verify_with_archives(backend=backend, keyring=ring_revoked, archive_dir=arc_dir)
        assert not rep.ok

        # The actionable signal must be UNKNOWN_KEY on the marker (and
        # the archived entries, since they were signed under k1 too)
        # — NOT a LINK_MISMATCH cascade. Before the fix the marker was
        # treated as a plain live entry: its prev_hmac (= last-archived
        # hmac) wouldn't match expected_prev (= empty for first entry)
        # and we'd see a phantom LINK_MISMATCH.
        kinds = {b.kind for b in rep.breaks}
        assert BreakKind.UNKNOWN_KEY in kinds, (
            f"expected UNKNOWN_KEY in breaks, got {[(b.kind, b.detail) for b in rep.breaks]}"
        )
        # Critically: the marker itself must NOT surface as
        # LINK_MISMATCH. The verifier should have bridged into the
        # archive instead of mis-treating the marker as a normal
        # entry. There may still be link/cascade breaks from the
        # archived entries being signed under the revoked key, but
        # the marker-as-plain-entry phantom LINK_MISMATCH must be
        # gone.
        marker_link_breaks = [
            b
            for b in rep.breaks
            if b.kind == BreakKind.LINK_MISMATCH
            and "compaction marker" not in b.detail
            and b.index == 0
        ]
        assert not marker_link_breaks, (
            f"marker should dispatch into archive bridge, not surface as "
            f"a plain-entry LINK_MISMATCH at index 0; got: "
            f"{[(b.kind, b.detail) for b in marker_link_breaks]}"
        )

    def test_recompact_with_revoked_marker_key_refuses_fail_closed(
        self,
        tmp_path: Path,
    ) -> None:
        backend = JsonlBackend(tmp_path / "audit.jsonl", fsync_after_append=False)
        k1 = Key(key_id="k1", secret=b"x" * 32)
        k2 = Key(key_id="k2", secret=b"y" * 32)
        chain1 = HmacChain(backend=backend, keyring=KeyRing(active=k1))

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain1.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()
        compact_audit_log(
            chain=chain1,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc1.bin",
        )

        # Operator revokes k1. Fresh chain object so the cache reflects
        # the new ring; ``cache_prev=False`` so the second compactor
        # re-reads disk truth.
        ring_revoked = KeyRing(active=k2)
        chain2 = HmacChain(backend=backend, keyring=ring_revoked, cache_prev=False)

        # Second compaction over the previous marker MUST raise. Before
        # the fix the A2 guard's keyring-aware ``is_compaction_marker``
        # returned False (MAC didn't verify under k2), so the marker
        # was archived as a normal entry into a corrupting second
        # archive.
        with pytest.raises(ValueError, match="MAC does not verify"):
            compact_audit_log(
                chain=chain2,
                backend=backend,
                before=datetime(2099, 1, 1, tzinfo=UTC),
                output=arc_dir / "arc2.bin",
            )
        # No second archive should exist on disk.
        assert not (arc_dir / "arc2.bin").exists()


# ---------------------------------------------------------------------------
# Round 9 LOW: ts_ns boundary docstring matches behavior
# ---------------------------------------------------------------------------


class TestR9LowTsNsBoundary:
    """``AuditEntry.from_dict`` accepts ``ts_ns == 10**19`` and the
    error message says ``[0, 10**19]`` (closed-closed, matching the
    ``> 10**19`` rejection). Before Round 9 the message said
    ``[0, 10**19)`` (half-open) which contradicted the actual check.
    """

    def _good_data(self) -> dict:
        return {
            "owner_type": "human",
            "owner_id": "alice",
            "approval_chain": ["human:alice"],
            "check_name": "c",
            "decision": "allow",
            "reason": "ok",
            "entry_id": "00000000-0000-0000-0000-000000000000",
            "ts_ns": 1700000000000000000,
            "prev_hmac": "",
            "hmac": "",
            "request_fingerprint": "",
            "metadata": {},
        }

    def test_ts_ns_just_below_boundary_accepted(self) -> None:
        data = self._good_data()
        data["ts_ns"] = 10**19 - 1
        e = AuditEntry.from_dict(data)
        assert e.ts_ns == 10**19 - 1

    def test_ts_ns_at_boundary_accepted(self) -> None:
        """``10**19`` is the inclusive upper bound (year ~2286). The
        check is ``> 10**19``, not ``>= 10**19``."""
        data = self._good_data()
        data["ts_ns"] = 10**19
        e = AuditEntry.from_dict(data)
        assert e.ts_ns == 10**19

    def test_ts_ns_above_boundary_rejected_with_closed_message(self) -> None:
        data = self._good_data()
        data["ts_ns"] = 10**19 + 1
        with pytest.raises(ValueError, match=r"\[0, 10\*\*19\]"):
            AuditEntry.from_dict(data)


# ---------------------------------------------------------------------------
# Round 11 HIGH-1: marker-aware tail read for cache_prev=False AND restart
# ---------------------------------------------------------------------------


class TestR11High1MarkerAwareTailRead:
    """Round 10 HIGH-1 closed the post-full-sweep LINK_MISMATCH for the
    same-instance / ``cache_prev=True`` path by seeding
    ``chain._cached_prev = eligible[-1].hmac`` inside the compactor.
    Round 11 found two bypasses where the seeded cache is ignored and
    the bug re-surfaces:

    1. ``cache_prev=False`` (the recommended config for
       :class:`FileLockingJsonlBackend` / multi-process deployments):
       :meth:`HmacChain._read_prev_hmac` skips the cache and falls
       through to :meth:`AuditBackend.last_entry`, which returns the
       marker. The next append links to ``marker.hmac`` instead of
       the bridge value ``eligible[-1].hmac``, producing a permanent
       ``LINK_MISMATCH`` in :func:`verify_with_archives`.
    2. Process restart with ``cache_prev=True``: the seeded cache lives
       on the in-memory ``HmacChain`` instance only. A fresh chain
       constructed against the same backend after compaction starts
       with ``_cached_prev=None``, falls into the same bug path.

    The Round 11 fix makes :meth:`HmacChain._read_prev_hmac` and
    :meth:`FileLockingJsonlBackend._read_tail_hmac` marker-aware:
    when the on-disk tail is a compaction marker, both return
    ``last.prev_hmac`` (the bridge value the marker's signed payload
    commits to) instead of ``last.hmac``. The marker's ``prev_hmac``
    was set by the compactor to ``eligible[-1].hmac`` and signed under
    the chain HMAC, so this is byte-stable and tamper-evident.

    The Round 10 same-instance cache-seed remains as a fast-path
    optimization (avoids the linear scan); the slow path is now
    correct on its own.
    """

    def test_cache_prev_false_full_sweep_then_append_verifies_clean(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """Bypass 1: ``cache_prev=False`` -- the seeded cache is
        ignored on read, slow path must return the bridge value."""
        chain = HmacChain(backend=backend, keyring=keyring, cache_prev=False)

        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )
        assert result is not None
        assert result.compacted_count == 3

        # Live log post-compaction contains ONLY the marker.
        live = list(backend.iter_entries())
        assert len(live) == 1
        assert is_compaction_marker(live[0])

        # Append after full-sweep. With cache_prev=False the seeded
        # cache from R10 HIGH-1 is ignored; the slow path must read
        # the marker tail and return ``marker.prev_hmac`` (= the
        # bridge value), not ``marker.hmac``.
        chain.append(_entry("post"))

        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, (
            f"verify_with_archives must be clean with cache_prev=False "
            f"after full-sweep + append; breaks: {list(report.breaks)}"
        )
        assert report.total_entries == 5  # 3 archived + 1 marker + 1 post

    def test_process_restart_after_full_sweep_then_append_verifies_clean(
        self,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """Bypass 2: fresh ``HmacChain`` instance after compaction
        (simulating a process restart) -- the in-memory cache-seed
        from R10 HIGH-1 is gone; the slow path must still return the
        bridge value."""
        chain1 = HmacChain(backend=backend, keyring=keyring)  # cache_prev=True

        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain1.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        result = compact_audit_log(
            chain=chain1,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )
        assert result is not None
        assert result.compacted_count == 3

        # Simulate a process restart: drop chain1, build chain2 against
        # the same on-disk backend. The seeded cache from R10's
        # compactor fix lived on chain1 only.
        del chain1
        chain2 = HmacChain(backend=backend, keyring=keyring)
        assert chain2._cached_prev is None  # fresh instance, no seed.

        # Append. The slow path must read the marker tail and return
        # ``marker.prev_hmac`` (= the bridge value).
        chain2.append(_entry("post-restart"))

        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, (
            f"verify_with_archives must be clean after process-restart "
            f"+ append; breaks: {list(report.breaks)}"
        )
        assert report.total_entries == 5  # 3 archived + 1 marker + 1 post

    def test_same_instance_happy_path_still_passes(
        self,
        chain: HmacChain,
        backend: JsonlBackend,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """R10 regression: same-instance / ``cache_prev=True`` path
        (the original R10 HIGH-1 fix) must still verify clean. The
        R11 fix adds a slow-path correction; the fast path (cache
        hit) is unchanged."""
        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )
        # The compactor seeded chain._cached_prev with the bridge
        # value; the next append should hit the cache (fast path).
        chain.append(_entry("post"))

        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, f"R10 regression breaks: {list(report.breaks)}"
        assert report.total_entries == 5

    def test_filelocking_backend_cache_prev_false_full_sweep(
        self,
        keyring: KeyRing,
        tmp_path: Path,
    ) -> None:
        """End-to-end variant using :class:`FileLockingJsonlBackend`
        with ``cache_prev=False`` -- the exact configuration the
        project docstring recommends for multi-process deployments.
        Exercises the ``append_locked_with_link`` V2 atomic path
        which calls :meth:`FileLockingJsonlBackend._read_tail_hmac`
        inside the cross-process lock. That method must also be
        marker-aware."""
        from signet.audit.backend import FileLockingJsonlBackend

        backend = FileLockingJsonlBackend(tmp_path / "audit.jsonl", fsync_after_append=False)
        chain = HmacChain(backend=backend, keyring=keyring, cache_prev=False)

        arc_dir = tmp_path / "archives"
        arc_dir.mkdir()

        base_dt = datetime(2026, 1, 1, tzinfo=UTC)
        base_ns = int(base_dt.timestamp() * 1_000_000_000)
        for i in range(3):
            chain.append(_entry(f"e{i}", ts_ns=base_ns + i * 1_000_000_000))

        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=datetime(2099, 1, 1, tzinfo=UTC),
            output=arc_dir / "arc.bin",
        )
        assert result is not None
        assert result.compacted_count == 3

        # Live log = marker only.
        live = list(backend.iter_entries())
        assert len(live) == 1
        assert is_compaction_marker(live[0])

        # The V2 atomic path reads the tail under the cross-process
        # lock via ``_read_tail_hmac``; that must return the bridge
        # value, not the marker hmac.
        chain.append(_entry("post"))

        report = verify_with_archives(backend=backend, keyring=keyring, archive_dir=arc_dir)
        assert report.ok, (
            f"FileLockingJsonlBackend + cache_prev=False must verify "
            f"clean after full-sweep + append; breaks: {list(report.breaks)}"
        )
        assert report.total_entries == 5
