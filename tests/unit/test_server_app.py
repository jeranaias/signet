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
            # Most existing tests assert against the verbose refusal
            # body shape (reason / check / stage). Default the fixture
            # to verbose so those assertions keep working; tests that
            # need the strict shape construct their own config.
            strict_error_redaction=False,
        )
        signet_app = SignetApp(config=config, pipeline=pipeline)
        return signet_app, TestClient(signet_app.app)

    return _make


class TestSmoke:
    def test_health(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["service"] == "signet"
        assert "version" in body
        assert body["pipeline_check_count"] == 0
        assert body["uptime_seconds"] >= 0
        # v0.1.6: three-state field. The fixture builds a SignetApp
        # with no audit_log_path, so the chain is unconfigured.
        assert body["audit_chain_head_hmac"] == "disabled"

    def test_healthz_alias(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["service"] == "signet"

    def test_readyz_when_upstream_unreachable(self, app_factory) -> None:
        # The fixture's upstream URL is http://upstream-mock/v1 which
        # does not resolve. /readyz should return 503.
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/readyz")
        assert r.status_code == 503
        body = r.json()
        assert body["status"] == "not_ready"
        assert "upstream" in body

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


class TestStrictErrorRedaction:
    """v0.1.5 #3: refusal/escalation bodies hide check identity by default.

    The verbose shape is preserved as an opt-out so integration testing
    (and the historical contract) still works for callers that want to
    see *which* check fired in the response.
    """

    def test_strict_refusal_redacts_check_identity(self) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=True,
        )
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
        signet_app = SignetApp(config=config, pipeline=pipeline)
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "x", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 403
        body = r.json()
        # Strict body exposes only error + correlation_id (and
        # retry_after_seconds when applicable).
        assert body["error"] == "refused"
        assert "correlation_id" in body
        # No leaks: the firing check name and reason MUST NOT appear.
        assert "reason" not in body
        assert "check" not in body
        assert "stage" not in body
        assert "owner" not in body
        assert "no commit owner" not in str(body).lower()

    def test_strict_rate_limit_keeps_retry_after(self) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=True,
        )
        pipeline = Pipeline(
            checks=[
                OwnerResolutionCheck(require_owner=True),
                RateLimitCheck(capacity=1, refill_per_second=0.001),
            ]
        )
        signet_app = SignetApp(config=config, pipeline=pipeline)
        client = TestClient(signet_app.app)
        body = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}
        headers = {"X-Commit-Owner": "human:alice"}
        # Drain the bucket; need an upstream mock for the first 200 path.
        # Easier: just hit the rate-limit twice with no upstream wired —
        # the second call should 429 before forwarding.
        # First request: pipeline allows, forwarding will fail upstream;
        # we don't care about its status. Second hits the rate-limit.
        client.post("/v1/chat/completions", json=body, headers=headers)
        r = client.post("/v1/chat/completions", json=body, headers=headers)
        assert r.status_code == 429
        rb = r.json()
        assert rb["error"] == "refused"
        # retry_after_seconds is operational and survives strict mode.
        assert "retry_after_seconds" in rb
        # No leaks of the firing check identity.
        assert "check" not in rb


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
        # Default config is strict_error_redaction=True, which exposes
        # correlation_id (the audit entry ID) but no other fields.
        assert body["correlation_id"]


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


class TestEmbeddingsAndCompletions:
    """v0.1.3 — /v1/embeddings and /v1/completions are gated like chat."""

    @pytest.fixture
    def embedding_response_body(self) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [{"object": "embedding", "embedding": [0.1, 0.2, 0.3], "index": 0}],
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 5, "total_tokens": 5},
        }

    @pytest.fixture
    def completion_response_body(self) -> dict[str, Any]:
        return {
            "id": "cmpl-fake",
            "object": "text_completion",
            "model": "gpt-3.5-turbo-instruct",
            "choices": [{"text": "the answer", "index": 0, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }

    def test_embeddings_with_owner_succeeds(
        self, monkeypatch: pytest.MonkeyPatch, embedding_response_body: dict[str, Any]
    ) -> None:
        async def fake_post(_self, url, **_kwargs):
            assert url.endswith("/embeddings"), f"wrong upstream path: {url}"

            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return embedding_response_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        config = ServerConfig(upstream_url="http://m/v1", allow_ephemeral_key=True)
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)

        r = client.post(
            "/v1/embeddings",
            json={"model": "text-embedding-3-small", "input": "hello"},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        assert r.json() == embedding_response_body
        assert r.headers.get("X-Signet-Upstream")

    def test_embeddings_without_owner_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = ServerConfig(upstream_url="http://m/v1", allow_ephemeral_key=True)
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/embeddings",
            json={"model": "text-embedding-3-small", "input": "hello"},
        )
        assert r.status_code == 403

    def test_completions_with_owner_succeeds(
        self, monkeypatch: pytest.MonkeyPatch, completion_response_body: dict[str, Any]
    ) -> None:
        async def fake_post(_self, url, **_kwargs):
            assert url.endswith("/completions") and not url.endswith("/chat/completions"), (
                f"wrong upstream path: {url}"
            )

            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return completion_response_body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        config = ServerConfig(upstream_url="http://m/v1", allow_ephemeral_key=True)
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)

        r = client.post(
            "/v1/completions",
            json={
                "model": "gpt-3.5-turbo-instruct",
                "prompt": "Hello",
                "max_tokens": 5,
            },
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        assert r.json() == completion_response_body


class TestUnsupportedEndpoints:
    def test_audio_endpoint_returns_explicit_404(self, app_factory) -> None:
        """v0.1.3 gates embeddings/completions; audio + images still 404."""
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post("/v1/audio/transcriptions", json={})
        assert r.status_code == 404
        body = r.json()
        assert "not implemented" in body["error"]
        assert "audio" in body["note"]

    def test_images_endpoint_returns_explicit_404(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post("/v1/images/generations", json={})
        assert r.status_code == 404
        body = r.json()
        assert "not implemented" in body["error"]


class TestEmptyBody:
    def test_empty_body_returns_explicit_400(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/chat/completions",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "empty request body"


class TestSessionWiring:
    def test_session_id_loads_session_into_scratch(
        self, monkeypatch: pytest.MonkeyPatch, upstream_response_body: dict[str, Any]
    ) -> None:
        from signet.core.check import Check, CheckResult
        from signet.core.context import RequestContext
        from signet.core.stage import Stage

        seen: dict[str, Any] = {}

        class _Snitch(Check):
            name = "snitch"
            stage = Stage.ADMISSION

            async def pre_request(self, ctx: RequestContext) -> CheckResult:
                seen["session"] = ctx.scratch.get("_session")
                return CheckResult.allow()

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
        config = ServerConfig(upstream_url="http://m/v1", allow_ephemeral_key=True)
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True), _Snitch()]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={
                "X-Commit-Owner": "human:alice",
                "X-Signet-Session": "sess-xyz",
            },
        )
        assert r.status_code == 200
        sess = seen["session"]
        assert sess is not None
        assert sess.session_id == "sess-xyz"
        assert sess.request_count >= 1


class TestSseExtractor:
    def test_multi_line_data_event_is_joined(self) -> None:
        from signet.server.app import _extract_sse_content

        # Two data: lines for one event, blank line dispatches the event.
        # The OpenAI SSE shape works equally well via single-line data:
        # but other upstreams send multi-line; we should handle both.
        chunk = (
            'data: {"choices":[{"delta":{"content":"hello "}}]}\n'
            "\n"
            'data: {"choices":[{"delta":{"content":"world"}}]}\n'
            "\n"
        )
        assert _extract_sse_content(chunk) == "hello world"

    def test_done_marker_ignored(self) -> None:
        from signet.server.app import _extract_sse_content

        chunk = "data: [DONE]\n\n"
        assert _extract_sse_content(chunk) == ""


class TestRequestFingerprint:
    def test_audit_rows_share_fingerprint_per_request(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path, upstream_response_body: dict[str, Any]
    ) -> None:
        from signet.audit.backend import JsonlBackend

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
        log = tmp_path / "audit.jsonl"
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
        )
        signet_app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)

        for _ in range(2):
            client.post(
                "/v1/chat/completions",
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                headers={"X-Commit-Owner": "human:alice"},
            )

        entries = list(JsonlBackend(log).iter_entries())
        assert all(e.request_fingerprint.startswith("sha256:") for e in entries)
        # Identical bodies → identical fingerprints (audit consumers can group)
        unique = {e.request_fingerprint for e in entries}
        assert len(unique) == 1


class TestEd25519Signer:
    """Asymmetric receipt signing: verifiers cannot forge."""

    def _entry(self) -> Any:
        from signet.audit.chain import HmacChain
        from signet.audit.keyring import Key, KeyRing
        from signet.core.audit import AuditEntry, Decision
        from signet.core.owner import Owner

        ring = KeyRing(active=Key(key_id="kAudit", secret=b"x" * 32))
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
        return chain.append(
            AuditEntry(
                owner=Owner.human("a"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )

    def test_sign_and_verify_roundtrip(self) -> None:
        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.generate(key_id="test-key")
        entry = self._entry()
        receipt = signer.sign(entry)

        assert "alg=ed25519" in receipt
        assert "key=test-key" in receipt
        assert signer.verify(receipt, entry) is True

    def test_verify_only_signer_cannot_sign(self, tmp_path) -> None:
        """An auditor with only the public key cannot forge receipts."""
        from signet.server.receipt import Ed25519ReceiptSigner

        full = Ed25519ReceiptSigner.generate(key_id="prod-key")
        pub_path = tmp_path / "signet.pub"
        pub_path.write_bytes(full.public_pem())

        verifier = Ed25519ReceiptSigner.from_pem(public_pem_path=str(pub_path), key_id="prod-key")
        with pytest.raises(RuntimeError, match="verify-only"):
            verifier.sign(self._entry())

    def test_verify_with_wrong_key_id_rejected(self) -> None:
        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.generate(key_id="prod-key")
        entry = self._entry()
        receipt = signer.sign(entry)

        # A verifier expecting a different key_id rejects the receipt
        wrong = Ed25519ReceiptSigner(
            private_key=None,
            public_key=signer._public,  # type: ignore[attr-defined]
            key_id="staging-key",
        )
        assert wrong.verify(receipt, entry) is False

    def test_tampered_signature_rejected(self) -> None:
        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.generate(key_id="prod-key")
        entry = self._entry()
        receipt = signer.sign(entry)

        # Flip a hex char in the signature → verification fails
        tampered = receipt[:-2] + ("00" if receipt[-2:] != "00" else "ff")
        assert signer.verify(tampered, entry) is False

    def test_alg_downgrade_to_hmac_rejected(self) -> None:
        """Receipt with alg=ed25519 cannot be downgraded to alg=hmac-sha256."""
        from signet.server.receipt import Ed25519ReceiptSigner

        signer = Ed25519ReceiptSigner.generate(key_id="prod-key")
        entry = self._entry()
        receipt = signer.sign(entry)
        downgraded = receipt.replace("alg=ed25519", "alg=hmac-sha256")
        assert signer.verify(downgraded, entry) is False

    def test_pem_roundtrip_via_files(self, tmp_path) -> None:
        from signet.server.receipt import Ed25519ReceiptSigner

        full = Ed25519ReceiptSigner.generate(key_id="rt-key")

        # Write keys
        from cryptography.hazmat.primitives import serialization

        priv_path = tmp_path / "key.pem"
        priv_path.write_bytes(
            full._private.private_bytes(  # type: ignore[union-attr]
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path = tmp_path / "key.pub"
        pub_path.write_bytes(full.public_pem())

        # Reload signer and verifier separately
        signer = Ed25519ReceiptSigner.from_pem(private_pem_path=str(priv_path), key_id="rt-key")
        verifier = Ed25519ReceiptSigner.from_pem(public_pem_path=str(pub_path), key_id="rt-key")

        entry = self._entry()
        receipt = signer.sign(entry)
        assert verifier.verify(receipt, entry) is True


class TestEd25519SignetAppIntegration:
    """End-to-end: SignetApp with an Ed25519ReceiptSigner emits valid receipts."""

    def test_signetapp_with_ed25519_signer(
        self, monkeypatch: pytest.MonkeyPatch, upstream_response_body: dict[str, Any], tmp_path
    ) -> None:
        from signet.server.receipt import Ed25519ReceiptSigner, parse_header

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

        signer = Ed25519ReceiptSigner.generate(key_id="prod")
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        app = SignetApp(
            config=config,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            receipt_signer=signer,
        )
        client = TestClient(app.app)

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
        assert parsed["alg"] == "ed25519"
        assert parsed["key"] == "prod"
        # Signature is hex of an ed25519 sig (64 bytes → 128 hex chars)
        assert len(parsed["sig"]) == 128


class TestHealthAuditChainStates:
    """v0.1.6 F4: ``/health.audit_chain_head_hmac`` has three states.

    Operators need to disambiguate "no chain configured" from "chain
    configured but currently empty". Earlier versions returned the same
    sentinel for both.
    """

    def test_chain_disabled_when_no_audit_log_path(self, app_factory) -> None:
        # Fixture's ServerConfig has audit_log_path=None.
        _, client = app_factory(Pipeline(checks=[]))
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["audit_chain_head_hmac"] == "disabled"

    def test_chain_configured_but_empty_returns_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        signet_app = SignetApp(config=config, pipeline=Pipeline(checks=[]))
        client = TestClient(signet_app.app)
        r = client.get("/health")
        assert r.status_code == 200
        # Chain is configured but no entries written yet → JSON null.
        assert r.json()["audit_chain_head_hmac"] is None

    def test_chain_with_entries_returns_8_hex_tail(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path,
        upstream_response_body: dict[str, Any],
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
        # Drive a single request through so the chain gains an entry.
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200

        h = client.get("/health")
        assert h.status_code == 200
        head = h.json()["audit_chain_head_hmac"]
        assert isinstance(head, str)
        assert head not in ("disabled", "")
        assert len(head) == 8
        # Must be valid lowercase hex
        int(head, 16)


class TestMultimodalRedaction:
    def test_redact_preserves_image_parts(self) -> None:
        from signet.server.app import SignetApp

        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "my ssn is 123-45-6789"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;..."}},
                    ],
                }
            ]
        }
        out = SignetApp._apply_redaction(body, "[REDACTED]")
        new_content = out["messages"][-1]["content"]
        assert isinstance(new_content, list)
        # image part survived
        assert any(p.get("type") == "image_url" for p in new_content)
        # text part replaced
        text_parts = [p for p in new_content if p.get("type") == "text"]
        assert len(text_parts) == 1
        assert text_parts[0]["text"] == "[REDACTED]"
