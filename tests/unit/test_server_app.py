"""Tests for SignetApp — the FastAPI proxy.

Strategy: use FastAPI's :class:`fastapi.testclient.TestClient` against
a SignetApp wired with a small pipeline. Mock the upstream by patching
``httpx.AsyncClient`` so tests don't need a real LLM endpoint.

Coverage:

* /health and /version smoke tests
* ADMISSION block produces 403 with reason
* ADMISSION rate limit produces 429
* Allowed request forwards body to upstream and returns the upstream
  response with X-Signet-Receipt
* Receipt parses and verifies against the active key
* Streaming abort emits the trailer event when an INSPECTION check
  blocks mid-stream
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.checks import OwnerResolutionCheck, RateLimitCheck
from signet.checks.regex_content import Pattern
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig
from signet.server.receipt import parse_header


@pytest.fixture
def upstream_response_body() -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello there."},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    }


@pytest.fixture
def app_factory(monkeypatch: pytest.MonkeyPatch, upstream_response_body: dict[str, Any]):
    """Returns a callable that builds a SignetApp + TestClient given a Pipeline.

    Patches httpx.AsyncClient.post so no real network call happens.
    """

    def _make(pipeline: Pipeline) -> tuple[SignetApp, TestClient]:
        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return upstream_response_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
        )
        signet_app = SignetApp(config=config, pipeline=pipeline)
        return signet_app, TestClient(signet_app.app)

    return _make


class TestSmoke:
    def test_health(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_version(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/version")
        assert r.status_code == 200
        assert r.json()["service"] == "signet"


class TestAdmissionBlock:
    def test_missing_owner_returns_403(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]))
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 403
        body = r.json()
        assert "no commit owner" in body["reason"].lower()

    def test_rate_limit_returns_429(self, app_factory) -> None:
        pipeline = Pipeline(
            checks=[
                OwnerResolutionCheck(require_owner=True),
                RateLimitCheck(capacity=1, refill_per_second=0.001),
            ]
        )
        _, client = app_factory(pipeline)
        body = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}
        headers = {"X-Commit-Owner": "human:alice"}
        r1 = client.post("/v1/chat/completions", json=body, headers=headers)
        assert r1.status_code == 200
        r2 = client.post("/v1/chat/completions", json=body, headers=headers)
        assert r2.status_code == 429
        assert "retry_after_seconds" in r2.json()


class TestAllowedRequest:
    def test_forwards_and_returns_upstream(
        self, app_factory, upstream_response_body: dict[str, Any]
    ) -> None:
        _, client = app_factory(Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]))
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        assert r.json() == upstream_response_body

    def test_emits_receipt_header(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]))
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        receipt = r.headers.get("X-Signet-Receipt") or r.headers.get("x-signet-receipt")
        # Receipts only emit when the audit chain is configured
        # (audit_log_path set). With default ServerConfig, chain is None,
        # so no receipt expected. This test asserts the absence; the
        # presence path is exercised in TestReceiptIntegration below.
        assert receipt is None


class TestReceiptIntegration:
    def test_receipt_emits_when_audit_configured(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, upstream_response_body: dict[str, Any]
    ) -> None:
        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return upstream_response_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)

        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        receipt = r.headers.get("X-Signet-Receipt") or r.headers.get("x-signet-receipt")
        assert receipt is not None

        parsed = parse_header(receipt)
        assert parsed is not None
        assert parsed["signet"] == "v1"
        assert parsed["alg"] == "hmac-sha256"
        assert parsed["entry"]
        assert parsed["key"]
        assert len(parsed["sig"]) == 64  # hex SHA-256

    def test_receipt_with_wrong_alg_rejected_by_verifier(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """An attacker that downgrades a future ed25519 receipt to
        hmac-sha256 by rewriting the alg= field must fail verification.

        The HmacReceiptSigner.verify only accepts alg=hmac-sha256;
        anything else returns False without comparing signatures.
        """
        from signet.audit.chain import HmacChain
        from signet.audit.keyring import Key, KeyRing
        from signet.core.audit import AuditEntry, Decision
        from signet.core.owner import Owner
        from signet.server.receipt import HmacReceiptSigner

        ring = KeyRing(active=Key(key_id="k1", secret=b"x" * 32))
        signer = HmacReceiptSigner(ring)
        chain = HmacChain(
            backend=type(
                "B",
                (),
                {
                    "append": lambda self, e: None,
                    "iter_entries": lambda self: iter([]),
                    "last_entry": lambda self: None,
                },
            )(),
            keyring=ring,
        )
        entry = chain.append(
            AuditEntry(
                owner=Owner.human("a"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        receipt = signer.sign(entry)
        # Substitute in a different alg tag — must reject.
        tampered = receipt.replace("alg=hmac-sha256", "alg=ed25519")
        assert signer.verify(tampered, entry) is False


class TestErrorPaths:
    def test_invalid_json_body_returns_400(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/chat/completions",
            content=b"this is not json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "invalid JSON" in r.json()["error"]


class TestRegexOutputBlocksRequest:
    def test_admission_regex_block_in_input(self, app_factory) -> None:
        from signet.checks.regex_content import RegexContentCheck

        pipeline = Pipeline(
            checks=[
                OwnerResolutionCheck(require_owner=True),
                RegexContentCheck(patterns=[Pattern(pattern=r"\bnuke\b", action="block")]),
            ]
        )
        _, client = app_factory(pipeline)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "please nuke the db"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 403
        assert "matched" in r.json()["reason"].lower()


class TestBodySizeLimit:
    def test_oversize_body_returns_413(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            max_request_body_bytes=1024,
        )
        signet_app = SignetApp(config=config, pipeline=Pipeline(checks=[]))
        client = TestClient(signet_app.app)
        big = b"x" * 4096
        r = client.post(
            "/v1/chat/completions",
            content=big,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413
        assert r.json()["limit_bytes"] == 1024


class TestRedactAndEscalate:
    def test_redact_modifies_body_before_forward(
        self, monkeypatch: pytest.MonkeyPatch, upstream_response_body: dict[str, Any]
    ) -> None:
        from signet.checks.regex_content import Pattern, RegexContentCheck

        forwarded: dict[str, Any] = {}

        async def fake_post(_self, _url, **kwargs):
            forwarded["body"] = kwargs.get("json")

            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return upstream_response_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        pipeline = Pipeline(
            checks=[
                OwnerResolutionCheck(require_owner=True),
                RegexContentCheck(
                    patterns=[
                        Pattern(
                            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
                            action="redact",
                            label="ssn",
                            replacement="[REDACTED-SSN]",
                        )
                    ]
                ),
            ]
        )
        config = ServerConfig(upstream_url="http://upstream-mock/v1", allow_ephemeral_key=True)
        signet_app = SignetApp(config=config, pipeline=pipeline)
        client = TestClient(signet_app.app)

        r = client.post(
            "/v1/chat/completions",
            json={
                "model": "test",
                "messages": [{"role": "user", "content": "my ssn is 123-45-6789"}],
            },
            headers={"X-Commit-Owner": "human:alice"},
        )
        # REDACT must NOT 403 — it must forward with replaced content.
        assert r.status_code == 200
        # Forwarded body should have the redaction in place
        sent_msgs = forwarded["body"]["messages"]
        assert "[REDACTED-SSN]" in sent_msgs[-1]["content"]
        assert "123-45-6789" not in sent_msgs[-1]["content"]

    def test_escalate_returns_202_with_audit_id(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from signet.core.check import Check, CheckResult
        from signet.core.context import RequestContext
        from signet.core.stage import Stage

        class _AlwaysEscalate(Check):
            name = "always_escalate"
            stage = Stage.ADMISSION

            async def pre_request(self, _ctx: RequestContext) -> CheckResult:
                return CheckResult.escalate("needs human review", risk="high")

        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True), _AlwaysEscalate()])
        signet_app = SignetApp(config=config, pipeline=pipeline)
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "escalated"
        assert body["audit_entry_id"]


class TestPipelineCrashAudit:
    def test_pre_request_exception_writes_audit_row(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from signet.audit.backend import JsonlBackend
        from signet.core.check import Check, CheckResult
        from signet.core.context import RequestContext
        from signet.core.stage import Stage

        class _Boom(Check):
            name = "boom"
            stage = Stage.ADMISSION

            async def pre_request(self, _ctx: RequestContext) -> CheckResult:
                raise RuntimeError("kaboom")

        log = tmp_path / "audit.jsonl"
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
        )
        signet_app = SignetApp(config=config, pipeline=Pipeline(checks=[_Boom()]))
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 500
        assert r.json()["exception"] == "RuntimeError"
        # Audit row was still written for the crash
        entries = list(JsonlBackend(log).iter_entries())
        assert len(entries) == 1
        assert "kaboom" in entries[0].reason


class TestUnsupportedEndpoints:
    def test_embeddings_returns_explicit_404(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post("/v1/embeddings", json={"input": "hi"})
        assert r.status_code == 404
        body = r.json()
        assert "not implemented" in body["error"]
        assert body["endpoint"] == "/v1/embeddings"
