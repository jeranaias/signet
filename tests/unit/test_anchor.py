"""Tests for anchor backends and the chain's anchor-receipt embedding.

The default NoopAnchor preserves byte-identical v0.1.2 chain behavior;
real anchor backends (Rfc3161Anchor) write a receipt into each entry's
metadata under ``_anchor`` so external auditors can prove the entry's
HMAC existed at a point in time. The HMAC binds the receipt back to
the entry, so swapping in a forged anchor breaks the chain.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from signet.audit.anchor import (
    ANCHOR_FIELD,
    AnchorReceipt,
    NoopAnchor,
    Rfc3161Anchor,
)
from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.audit.verifier import ChainVerifier
from signet.core.audit import AuditEntry, Decision
from signet.core.owner import Owner


def _entry(reason: str = "test") -> AuditEntry:
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


class TestNoopAnchor:
    def test_default_anchor_is_noop_and_chain_verifies(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        chain = HmacChain(backend, keyring)
        chain.append(_entry("first"))
        chain.append(_entry("second"))

        report = ChainVerifier(backend, keyring).verify()
        assert report.ok
        assert report.total_entries == 2

    def test_noop_anchor_embeds_metadata_marker(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        """Even Noop writes an _anchor marker so consumers can see anchoring
        was attempted (vs. a pre-anchor v0.1.2 chain that has no marker)."""
        chain = HmacChain(backend, keyring, anchor=NoopAnchor())
        appended = chain.append(_entry("only"))
        assert ANCHOR_FIELD in appended.metadata
        anchor = appended.metadata[ANCHOR_FIELD]
        assert anchor["backend"] == "noop"
        assert anchor["success"] is True


class TestAnchorReceiptBinding:
    def test_swapping_anchor_receipt_breaks_chain(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        """Tamper test: replace _anchor receipt → chain HMAC must fail."""
        chain = HmacChain(backend, keyring, anchor=NoopAnchor())
        chain.append(_entry("clean"))

        # Mutate the on-disk _anchor field
        lines = backend.path.read_text(encoding="utf-8").splitlines()
        d = json.loads(lines[0])
        d["metadata"][ANCHOR_FIELD] = {"backend": "forged", "success": True}
        lines[0] = json.dumps(d, separators=(",", ":"), sort_keys=True)
        backend.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = ChainVerifier(backend, keyring).verify()
        assert not report.ok
        # The HMAC binds the original anchor receipt, so swapping it
        # produces a SELF_MISMATCH on the entry whose metadata we changed.
        from signet.audit.verifier import BreakKind

        assert any(b.kind is BreakKind.SELF_MISMATCH for b in report.breaks)


class TestFailingAnchorBackends:
    """An anchor backend that returns success=False writes a flagged entry."""

    def test_failing_anchor_writes_entry_with_failure_note(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        from dataclasses import dataclass

        @dataclass
        class _FailingAnchor:
            name: str = "unreachable"

            def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
                return AnchorReceipt(
                    backend=self.name,
                    success=False,
                    error="connection refused",
                )

        chain = HmacChain(backend, keyring, anchor=_FailingAnchor())
        appended = chain.append(_entry("failed-anchor"))

        # Entry is still written; chain still verifies internally
        assert ANCHOR_FIELD in appended.metadata
        assert appended.metadata[ANCHOR_FIELD]["success"] is False
        assert "connection refused" in appended.metadata[ANCHOR_FIELD]["error"]
        assert ChainVerifier(backend, keyring).verify().ok

    def test_require_anchor_success_raises_on_failure(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        from dataclasses import dataclass

        @dataclass
        class _FailingAnchor:
            name: str = "unreachable"

            def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
                return AnchorReceipt(backend=self.name, success=False, error="oops")

        chain = HmacChain(backend, keyring, anchor=_FailingAnchor(), require_anchor_success=True)
        with pytest.raises(RuntimeError, match="failed"):
            chain.append(_entry("must-anchor"))

    def test_anchor_raising_exception_translated_to_failure(
        self, backend: JsonlBackend, keyring: KeyRing
    ) -> None:
        """An anchor backend that raises is treated as a failure (not a crash)
        unless require_anchor_success=True."""
        from dataclasses import dataclass

        @dataclass
        class _CrashingAnchor:
            name: str = "crashing"

            def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
                raise ConnectionError("network down")

        chain = HmacChain(backend, keyring, anchor=_CrashingAnchor())
        appended = chain.append(_entry("crashed-anchor"))
        assert appended.metadata[ANCHOR_FIELD]["success"] is False
        assert "ConnectionError" in appended.metadata[ANCHOR_FIELD]["error"]


class TestRfc3161AnchorOffline:
    """Tests that don't require network — exercise the request-builder path."""

    def test_tsr_request_construction_for_known_hmac(self) -> None:
        """A SHA-256 digest produces a well-formed TimeStampReq."""
        anchor = Rfc3161Anchor()
        # 32-byte digest
        digest = b"a" * 32
        tsr = anchor._build_tsr(digest)
        # Starts with SEQUENCE tag
        assert tsr[0] == 0x30
        # Contains the SHA-256 OID DER
        assert bytes.fromhex("0609608648016503040201") in tsr
        # Contains our digest as octet string
        assert digest in tsr

    def test_invalid_digest_length_raises(self) -> None:
        anchor = Rfc3161Anchor()
        with pytest.raises(ValueError, match="32 bytes"):
            anchor._build_tsr(b"too-short")

    def test_unreachable_tsa_returns_failure_receipt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Network failure → returns success=False with error, does not raise."""
        anchor = Rfc3161Anchor(tsa_url="http://127.0.0.1:1/tsr", timeout_s=0.5)

        def fake_post(*args, **kwargs):
            raise httpx.ConnectError("simulated DNS failure")

        monkeypatch.setattr(httpx, "post", fake_post)
        receipt = anchor.anchor_hmac("a" * 64)
        assert receipt.success is False
        assert "ConnectError" in receipt.error
        assert receipt.anchor_url == "http://127.0.0.1:1/tsr"

    def test_successful_tsa_response_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 200 from the TSA is base64-recorded in the receipt."""
        anchor = Rfc3161Anchor(tsa_url="http://fake-tsa/tsr")

        class FakeResp:
            status_code = 200
            content = b"\x30\x82\x01\x42fake-TST-DER-bytes"

            def raise_for_status(self) -> None:
                pass

        def fake_post(*args, **kwargs):
            return FakeResp()

        monkeypatch.setattr(httpx, "post", fake_post)
        receipt = anchor.anchor_hmac("a" * 64)
        assert receipt.success is True
        assert receipt.anchor_url == "http://fake-tsa/tsr"
        # Receipt is base64-encoded
        import base64

        assert base64.b64decode(receipt.receipt) == FakeResp.content
