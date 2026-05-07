"""Tests for signet.audit — the HMAC chain end-to-end.

Coverage targets:

* Roundtrip: append N entries, verify clean.
* Tamper detection — every kind of break the verifier names:
  - SELF_MISMATCH (entry payload modified)
  - LINK_MISMATCH (insertion, deletion, reordering)
  - UNKNOWN_KEY (key ring missing a legacy key)
  - MISSING_KEY_ID (entry has no signing-key marker)
* Key rotation: rotate, append under new key, verify spans both eras.
* Edge cases: empty chain, single-entry chain, many entries.

Tests use the JsonlBackend with tmp_path so each test gets a clean file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import BreakKind, ChainVerifier
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _entry(reason: str = "test") -> AuditEntry:
    """Build a fresh AuditEntry with stable owner+check_name+decision."""
    return AuditEntry(
        owner=Owner.human("alice@example.com"),
        check_name="owner_resolution",
        decision=Decision.ALLOW,
        reason=reason,
    )


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(active=Key.generate("k1"))


@pytest.fixture
def backend(tmp_path: Path) -> JsonlBackend:
    return JsonlBackend(tmp_path / "audit.jsonl")


@pytest.fixture
def chain(backend: JsonlBackend, keyring: KeyRing) -> HmacChain:
    return HmacChain(backend=backend, keyring=keyring)


class TestRoundtrip:
    def test_empty_chain_verifies_clean(self, backend: JsonlBackend, keyring: KeyRing) -> None:
        report = ChainVerifier(backend, keyring).verify()
        assert report.ok
        assert report.total_entries == 0
        assert report.last_known_good_index == -1

    def test_single_entry_verifies_clean(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        appended = chain.append(_entry("first"))
        assert appended.hmac  # populated
        assert appended.prev_hmac == ""  # first entry has no predecessor

        report = ChainVerifier(backend, keyring).verify()
        assert report.ok
        assert report.total_entries == 1
        assert report.last_known_good_index == 0
        assert report.last_known_good_hmac == appended.hmac

    def test_many_entries_verify_clean(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        for i in range(50):
            chain.append(_entry(f"entry-{i}"))

        report = ChainVerifier(backend, keyring).verify()
        assert report.ok
        assert report.total_entries == 50
        assert report.last_known_good_index == 49

    def test_each_entry_links_to_predecessor(self, chain: HmacChain, backend: JsonlBackend) -> None:
        a = chain.append(_entry("a"))
        b = chain.append(_entry("b"))
        c = chain.append(_entry("c"))

        assert a.prev_hmac == ""
        assert b.prev_hmac == a.hmac
        assert c.prev_hmac == b.hmac


class TestSelfMismatchDetection:
    def test_modified_reason_detected(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("first"))
        chain.append(_entry("second"))

        # Tamper: change the second entry's reason after the fact
        lines = backend.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["reason"] = "AFTER-TAMPERED"
        lines[1] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        assert any(b.kind is BreakKind.SELF_MISMATCH and b.index == 1 for b in report.breaks)

    def test_modified_owner_detected(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("only"))

        lines = backend.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["owner_id"] = "mallory@evil.com"
        lines[0] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # Modified owner_id changes the payload, so HMAC won't match.
        assert any(b.kind is BreakKind.SELF_MISMATCH for b in report.breaks)


class TestLinkMismatchDetection:
    def test_deleted_middle_entry_detected(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        lines = backend.path.read_text(encoding="utf-8").splitlines()
        # Delete entry 'b'
        del lines[1]
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # 'c' is now at index 1, and its prev_hmac points at 'b' which is gone
        assert any(b.kind is BreakKind.LINK_MISMATCH and b.index == 1 for b in report.breaks)

    def test_reordered_entries_detected(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        chain.append(_entry("c"))

        lines = backend.path.read_text(encoding="utf-8").splitlines()
        # Swap b and c
        lines[1], lines[2] = lines[2], lines[1]
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # At least one link should mismatch after the swap
        assert any(b.kind is BreakKind.LINK_MISMATCH for b in report.breaks)

    def test_inserted_forged_entry_detected(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        a = chain.append(_entry("a"))
        chain.append(_entry("b"))

        # Insert a forged entry between them with random plausible-looking HMACs
        forged = _entry("forged").to_dict()
        forged["prev_hmac"] = a.hmac
        forged["hmac"] = "0" * 64  # not a real HMAC
        forged["metadata"] = {"_signing_key_id": "k1"}

        lines = backend.path.read_text(encoding="utf-8").splitlines()
        lines.insert(1, json.dumps(forged, separators=(",", ":"), sort_keys=True))
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # The forged entry will fail SELF_MISMATCH (fake HMAC),
        # AND the next entry will fail LINK_MISMATCH (its prev_hmac no longer
        # matches the new predecessor's hmac).
        kinds = {b.kind for b in report.breaks}
        assert BreakKind.SELF_MISMATCH in kinds or BreakKind.LINK_MISMATCH in kinds


class TestKeyRotation:
    def test_chain_spanning_rotation_verifies(self, backend: JsonlBackend) -> None:
        # Era 1
        ring = KeyRing(active=Key.generate("k1"))
        chain = HmacChain(backend, ring)
        chain.append(_entry("era1-a"))
        chain.append(_entry("era1-b"))

        # Rotate; era 2
        ring.rotate(Key.generate("k2"))
        chain2 = HmacChain(backend, ring)  # fresh chain instance with same backend+ring
        chain2.append(_entry("era2-a"))
        chain2.append(_entry("era2-b"))

        report = ChainVerifier(backend, ring).verify()
        assert report.ok, f"breaks: {report.breaks}"
        assert report.total_entries == 4

    def test_unknown_key_reported_distinctly(self, backend: JsonlBackend) -> None:
        # Sign two entries under k1
        ring = KeyRing(active=Key.generate("k1"))
        chain = HmacChain(backend, ring)
        chain.append(_entry("a"))
        chain.append(_entry("b"))

        # Try to verify with a ring that doesn't know k1
        empty_ring = KeyRing(active=Key.generate("kZ"))
        report = ChainVerifier(backend, empty_ring).verify()
        assert not report.ok
        assert all(b.kind is BreakKind.UNKNOWN_KEY for b in report.breaks)


class TestMissingKeyId:
    def test_entry_without_key_id_reported(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("legit"))

        # Drop the key ID metadata field
        lines = backend.path.read_text(encoding="utf-8").splitlines()
        d = json.loads(lines[0])
        d["metadata"] = {}  # strip _signing_key_id
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        assert any(b.kind is BreakKind.MISSING_KEY_ID for b in report.breaks)


class TestKeyRingValidation:
    def test_short_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            Key(key_id="too-short", secret=b"tiny")

    def test_empty_key_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            Key(key_id="", secret=b"x" * 32)

    def test_repr_does_not_leak_secret(self) -> None:
        # Regression: prior versions used the default dataclass repr,
        # which would print the raw secret in any log line or exception
        # trace that touched a Key. Redaction must be explicit.
        secret = b"super-sensitive-hmac-key-that-must-not-be-printed"
        k = Key(key_id="k1", secret=secret)
        rendered = repr(k)
        assert "super-sensitive" not in rendered
        assert "redacted" in rendered
        assert "k1" in rendered

    def test_rotate_to_same_id_rejected(self) -> None:
        ring = KeyRing(active=Key.generate("k1"))
        with pytest.raises(ValueError, match="same ID"):
            ring.rotate(Key.generate("k1"))

    def test_add_legacy_with_active_id_rejected(self) -> None:
        ring = KeyRing(active=Key.generate("k1"))
        with pytest.raises(ValueError, match="same ID as active"):
            ring.add_legacy(Key.generate("k1"))

    def test_duplicate_legacy_rejected(self) -> None:
        ring = KeyRing(active=Key.generate("k1"))
        ring.add_legacy(Key.generate("k0"))
        with pytest.raises(ValueError, match="already registered"):
            ring.add_legacy(Key.generate("k0"))

    def test_keys_list_constructor(self) -> None:
        # v0.1.5 #7 ergonomic alias.
        k1 = Key.generate("k1")
        k0 = Key.generate("k0")
        ring = KeyRing(keys=[k0, k1], active_id="k1")
        assert ring.active.key_id == "k1"
        assert ring.get("k0") is k0
        assert ring.all_known_ids() == ("k1", "k0")

    def test_keys_dict_constructor(self) -> None:
        k1 = Key.generate("k1")
        k0 = Key.generate("k0")
        ring = KeyRing(keys={"k1": k1, "k0": k0}, active_id="k0")
        assert ring.active.key_id == "k0"
        assert ring.get("k1") is k1

    def test_active_id_must_match_a_key(self) -> None:
        with pytest.raises(ValueError, match="not present"):
            KeyRing(keys=[Key.generate("k1")], active_id="missing")

    def test_keys_with_duplicates_rejected(self) -> None:
        # The list-shape constructor should refuse two Key objects
        # sharing the same key_id rather than silently last-wins.
        k1a = Key.generate("k1")
        k1b = Key.generate("k1")
        with pytest.raises(ValueError, match="duplicate key_id"):
            KeyRing(keys=[k1a, k1b], active_id="k1")

    def test_constructor_rejects_active_with_keys(self) -> None:
        # Mixing the historical and new shapes should fail loudly
        # rather than silently let one win.
        k = Key.generate("k1")
        with pytest.raises(ValueError, match="not both"):
            KeyRing(active=k, keys=[k], active_id="k1")

    def test_keyring_dict_form_wraps_bytes(self) -> None:
        # v0.1.6 B2 regression: dict-form keys=... with raw bytes values
        # had been stored unwrapped, so kr.active.key_id raised
        # AttributeError on a bytes object.
        kr = KeyRing(keys={"k1": b"x" * 32}, active_id="k1")
        assert isinstance(kr.active, Key)
        assert kr.active.key_id == "k1"
        assert kr.active.secret == b"x" * 32

    def test_keyring_dict_form_with_key_objects(self) -> None:
        k = Key(key_id="k1", secret=b"y" * 32)
        kr = KeyRing(keys={"k1": k}, active_id="k1")
        assert kr.active is k

    def test_keyring_legacy_active_form_still_works(self) -> None:
        k = Key(key_id="k1", secret=b"x" * 32)
        kr = KeyRing(active=k)
        assert kr.active is k


class TestConcurrentAppend:
    def test_concurrent_appends_do_not_fork_chain(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        """Threads racing through append must not fork the chain.

        Without the internal lock, two threads could both read the same
        ``prev_hmac`` before either wrote, producing two entries with
        the same predecessor. The verifier would then report a
        LINK_MISMATCH.
        """
        import threading

        N = 25
        barrier = threading.Barrier(N)

        def worker(i: int) -> None:
            barrier.wait()  # release all threads at once for max contention
            chain.append(_entry(f"e{i}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        report = ChainVerifier(backend, keyring).verify()
        assert report.ok, f"breaks: {report.breaks}"
        assert report.total_entries == N


class TestCanonicalization:
    def test_nan_in_metadata_is_rejected(self, chain: HmacChain, keyring: KeyRing) -> None:
        """NaN in metadata would produce non-canonical JSON
        (`NaN` literal that strict parsers reject), so the writer
        must refuse it loudly rather than silently produce an entry
        the verifier later rejects."""
        bad_entry = AuditEntry(
            owner=Owner.human("alice"),
            check_name="x",
            decision=Decision.ALLOW,
            reason="bad",
            metadata={"score": float("nan")},
        )
        with pytest.raises(ValueError, match="not JSON compliant"):
            chain.append(bad_entry)


class TestFileLockingBackend:
    """File-locking backend: multiple writers against one file stay linked."""

    def test_locking_backend_basic_append_and_verify(self, tmp_path: Path) -> None:
        from signet.audit.backend import FileLockingJsonlBackend

        backend = FileLockingJsonlBackend(tmp_path / "audit.jsonl")
        ring = KeyRing(active=Key.generate("k1"))
        chain = HmacChain(backend, ring, cache_prev=False)
        for i in range(5):
            chain.append(_entry(f"entry-{i}"))
        report = ChainVerifier(backend, ring).verify()
        assert report.ok
        assert report.total_entries == 5

    def test_two_chain_instances_share_file_safely(self, tmp_path: Path) -> None:
        """Two HmacChain instances against the same FileLockingJsonlBackend
        path simulate two uvicorn workers. With cache_prev=False, both
        read the chain head from disk under the lock and stay linked."""
        from signet.audit.backend import FileLockingJsonlBackend

        path = tmp_path / "audit.jsonl"
        ring = KeyRing(active=Key.generate("k1"))

        # Two separate backend + chain instances simulate two processes
        backend_a = FileLockingJsonlBackend(path)
        backend_b = FileLockingJsonlBackend(path)
        chain_a = HmacChain(backend_a, ring, cache_prev=False)
        chain_b = HmacChain(backend_b, ring, cache_prev=False)

        chain_a.append(_entry("a-1"))
        chain_b.append(_entry("b-1"))
        chain_a.append(_entry("a-2"))
        chain_b.append(_entry("b-2"))

        # Verify with a fresh reader
        verifier_backend = FileLockingJsonlBackend(path)
        report = ChainVerifier(verifier_backend, ring).verify()
        assert report.ok, f"breaks: {report.breaks}"
        assert report.total_entries == 4


class TestVerificationReportShape:
    def test_clean_report_attributes(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain.append(_entry("a"))
        chain.append(_entry("b"))
        report = ChainVerifier(backend, keyring).verify()
        assert report.ok
        assert report.total_entries == 2
        assert report.last_known_good_index == 1
        assert report.last_known_good_hmac

    def test_break_report_carries_index_and_id(
        self, chain: HmacChain, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        a = chain.append(_entry("a"))
        chain.append(_entry("b"))

        # Tamper with entry 0
        lines = backend.path.read_text(encoding="utf-8").splitlines()
        d = json.loads(lines[0])
        d["reason"] = "MUTATED"
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        breaks = [b for b in report.breaks if b.index == 0]
        assert breaks
        assert breaks[0].entry_id == a.entry_id
        assert "hmac" in breaks[0].detail.lower()
