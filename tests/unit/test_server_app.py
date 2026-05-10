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

    def test_health_includes_shadow_flag(self) -> None:
        # Default (shadow=False): /health body has shadow=False so the
        # field is always present and operators can tail it.
        cfg_off = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
        )
        client_off = TestClient(SignetApp(config=cfg_off, pipeline=Pipeline(checks=[])).app)
        body_off = client_off.get("/health").json()
        assert body_off["shadow"] is False

        # shadow=True: /health body has shadow=True so dashboards can
        # alert on "production gate is in pilot mode".
        cfg_on = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            shadow=True,
        )
        client_on = TestClient(SignetApp(config=cfg_on, pipeline=Pipeline(checks=[])).app)
        body_on = client_on.get("/health").json()
        assert body_on["shadow"] is True


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


class TestShadowMode:
    """v0.1.6 F1: shadow mode neutralizes block/escalate/redact at the
    response layer. Audit chain still records the original decision with
    metadata.shadow=True; the response carries X-Signet-Shadow-* headers
    and a correlation ID; the signet_shadow_would_have_blocked_total
    counter increments. Operators pilot signet in shadow mode against
    production traffic before flipping enforcement on.
    """

    @staticmethod
    def _patch_upstream(
        monkeypatch: pytest.MonkeyPatch, body: dict[str, Any] | None = None
    ) -> None:
        body = body or {
            "id": "x",
            "object": "chat.completion",
            "model": "m",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }

        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b""
                headers: ClassVar[dict[str, str]] = {}

                @staticmethod
                def json() -> dict[str, Any]:
                    return body

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    def test_admission_block_becomes_200_in_shadow_mode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from signet.audit.backend import JsonlBackend

        self._patch_upstream(monkeypatch)
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            shadow=True,
            strict_error_redaction=False,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        # Non-shadow would 403; shadow neutralizes to 200.
        assert r.status_code == 200
        assert r.headers.get("X-Signet-Shadow-Decision") == "block"
        assert r.headers.get("X-Signet-Shadow-Stage") == "admission"
        assert r.headers.get("X-Signet-Correlation-Id")
        # Audit row has shadow=True metadata; original decision survives.
        entries = list(JsonlBackend(log).iter_entries())
        shadowed = [e for e in entries if e.metadata.get("shadow") is True]
        assert len(shadowed) >= 1
        assert shadowed[0].decision.value == "block"

    def test_rate_limit_block_becomes_200_in_shadow_mode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        self._patch_upstream(monkeypatch)
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            shadow=True,
            strict_error_redaction=False,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(
                checks=[
                    OwnerResolutionCheck(require_owner=True),
                    RateLimitCheck(capacity=1, refill_per_second=0.001),
                ]
            ),
        )
        client = TestClient(signet_app.app)
        body = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}
        headers = {"X-Commit-Owner": "human:alice"}
        # First request consumes the bucket but is allowed.
        r1 = client.post("/v1/chat/completions", json=body, headers=headers)
        assert r1.status_code == 200
        # Second request would 429; shadow neutralizes to 200 with
        # X-Signet-Shadow-Decision: block (rate limit blocks; shadow
        # does NOT promote it to escalate).
        r2 = client.post("/v1/chat/completions", json=body, headers=headers)
        assert r2.status_code == 200
        assert r2.headers.get("X-Signet-Shadow-Decision") == "block"

    def test_escalation_becomes_200_in_shadow_mode(
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

        self._patch_upstream(monkeypatch)
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            shadow=True,
            strict_error_redaction=False,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(
                checks=[OwnerResolutionCheck(require_owner=True), _AlwaysEscalate()]
            ),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        # Without shadow this would be 202; shadow neutralizes to 200.
        assert r.status_code == 200
        assert r.headers.get("X-Signet-Shadow-Decision") == "escalate"

    def test_shadow_counter_increments(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        self._patch_upstream(monkeypatch)
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            shadow=True,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 200
        m = client.get("/metrics")
        assert m.status_code == 200
        text = m.text
        # Counter must be present and non-zero for the would-have-blocked
        # admission decision. Labels mirror signet_pipeline_decisions_total
        # so dashboards can join the two.
        assert "signet_shadow_would_have_blocked_total" in text
        # Find the counter line and confirm it is at least 1.0 (handle
        # any label ordering deterministically).
        hit = False
        for line in text.splitlines():
            if line.startswith("signet_shadow_would_have_blocked_total{") and 'decision="block"' in line:
                value = float(line.rsplit(" ", 1)[-1])
                assert value >= 1.0
                hit = True
        assert hit, "expected a signet_shadow_would_have_blocked_total{decision=\"block\"} sample"

    def test_shadow_correlation_id_matches_audit_entry(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from signet.audit.backend import JsonlBackend

        self._patch_upstream(monkeypatch)
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            shadow=True,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        corr_id = r.headers.get("X-Signet-Correlation-Id")
        assert corr_id
        entries = list(JsonlBackend(log).iter_entries())
        # The shadowed admission row must carry the same entry_id as the
        # X-Signet-Correlation-Id header — that is the contract that lets
        # operators pivot from response → audit chain.
        shadowed = [e for e in entries if e.metadata.get("shadow") is True]
        assert any(e.entry_id == corr_id for e in shadowed)


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


class TestNonDictBody:
    """v0.1.7 H1: non-dict JSON bodies must 400, not 500.

    ``json.loads`` happily parses a top-level list/scalar/null; downstream
    code assumed a dict and 500'd with AttributeError when it wasn't.
    Reject the request with a structured 400 instead so the audit chain
    isn't blamed for client errors.
    """

    @pytest.mark.parametrize(
        "raw",
        [
            b"[]",
            b"null",
            b"123",
            b'"hi"',
            b"true",
        ],
    )
    def test_non_dict_body_returns_400(self, app_factory, raw: bytes) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/chat/completions",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "request body must be a JSON object"
        assert "got_type" in body
        assert "expected" in body

    def test_completions_non_dict_body_returns_400(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/completions",
            content=b"[]",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "request body must be a JSON object"

    def test_embeddings_non_dict_body_returns_400(self, app_factory) -> None:
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/embeddings",
            content=b"42",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "request body must be a JSON object"

    def test_empty_body_message_is_actionable(self, app_factory) -> None:
        """L4: empty-body 400 carries an ``expected`` hint so callers
        can tell at a glance what shape the gate wants."""
        _, client = app_factory(Pipeline(checks=[]))
        r = client.post(
            "/v1/chat/completions",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "empty request body"
        assert "messages" in body["expected"]


class TestUpstreamNonJsonAttribution:
    """v0.1.7 H2: upstream non-JSON returns 502 WITH attribution headers.

    Without the headers, callers can't distinguish a 502 the upstream
    caused (a misconfigured backend, a 302 to an HTML login page, etc.)
    from a 502 signet itself produced.
    """

    def test_502_carries_upstream_attribution_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_post(_self, _url, **_kwargs):
            class FakeResp:
                status_code = 200
                content = b"<html>maintenance window</html>"
                headers: ClassVar[dict[str, str]] = {"content-type": "text/html"}

                @staticmethod
                def json() -> dict[str, Any]:
                    raise __import__("json").JSONDecodeError("bad", "doc", 0)

            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            upstream_label="test-upstream",
            allow_ephemeral_key=True,
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
        assert r.status_code == 502
        # Both attribution headers fire so callers can blame upstream.
        assert r.headers.get("X-Signet-Upstream") == "test-upstream"
        assert r.headers.get("X-Signet-Upstream-Status") == "200"
        # Body is the upstream's verbatim non-JSON content.
        assert b"maintenance window" in r.content


class TestUnsupportedEndpointVersion:
    """v0.1.7 H3: refusal body uses ``__version__``, not a hardcoded literal."""

    def test_refusal_body_uses_current_version(self, app_factory) -> None:
        from signet import __version__

        _, client = app_factory(Pipeline(checks=[]))
        r = client.post("/v1/audio/transcriptions", json={})
        assert r.status_code == 404
        body = r.json()
        # Body MUST name the live version, not a hardcoded older one.
        assert __version__ in body["error"]
        assert __version__ in body["note"]
        # And must NOT carry the historic v0.1.3 sentinel.
        assert "v0.1.3" not in body["error"]
        assert "v0.1.3" not in body["note"]


class TestAbortFrameTransportPreserved:
    """v0.1.7 S2: transport-reason abort frames survive strict redaction.

    A protocol violation, exception, or timeout is a wire-state condition
    SDKs must distinguish from a policy refusal so retry semantics work.
    Strict mode coarsens policy reasons but preserves transport reasons.
    """

    def test_strict_preserves_upstream_protocol_violation(self) -> None:
        from signet.server.app import SignetApp as _App

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=True,
        )
        app = _App(config=cfg, pipeline=Pipeline(checks=[]))
        frames = app._build_abort_frames(
            reason="upstream_protocol_violation",
            stage="inspection",
            check_name=None,
            entry=None,
        )
        # First frame holds the JSON payload; second is the [DONE] marker.
        body = frames[0].decode("utf-8").lstrip("data: ").strip()
        import json as _json

        payload = _json.loads(body)
        assert payload["reason"] == "upstream_protocol_violation"
        # Strict still drops check field.
        assert "check" not in payload

    def test_strict_coarsens_policy_reason_to_refused(self) -> None:
        from signet.server.app import SignetApp as _App

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=True,
        )
        app = _App(config=cfg, pipeline=Pipeline(checks=[]))
        frames = app._build_abort_frames(
            reason="output marker (S//NF) implies classification level 2",
            stage="inspection",
            check_name="scope_drift",
            entry=None,
        )
        import json as _json

        payload = _json.loads(frames[0].decode("utf-8").lstrip("data: ").strip())
        # Policy reason coarsened to ``refused``; check name dropped.
        assert payload["reason"] == "refused"
        assert "check" not in payload

    def test_verbose_keeps_full_reason_and_check(self) -> None:
        from signet.server.app import SignetApp as _App

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=False,
        )
        app = _App(config=cfg, pipeline=Pipeline(checks=[]))
        frames = app._build_abort_frames(
            reason="some policy reason",
            stage="inspection",
            check_name="scope_drift",
            entry=None,
        )
        import json as _json

        payload = _json.loads(frames[0].decode("utf-8").lstrip("data: ").strip())
        assert payload["reason"] == "some policy reason"
        assert payload["check"] == "scope_drift"


class TestSessionIdStripped:
    """v0.1.7 L6: trailing whitespace in X-Signet-Session is stripped.

    Some HTTP clients add whitespace when composing headers; an empty
    post-strip value should be treated as no-session, not a session
    indexed by the literal whitespace.
    """

    def test_whitespace_session_id_treated_as_unset(
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
                seen["session_id"] = ctx.session_id
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
                "X-Signet-Session": "   ",  # whitespace-only
            },
        )
        assert r.status_code == 200
        # Whitespace-only session ID is normalized to None — no
        # phantom session object created.
        assert seen["session_id"] is None
        assert seen["session"] is None

    def test_session_id_trimmed(
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
                seen["session_id"] = ctx.session_id
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
                "X-Signet-Session": "  sess-abc  ",
            },
        )
        assert r.status_code == 200
        assert seen["session_id"] == "sess-abc"


class TestCorsCredentialsWildcardWarn:
    """v0.1.7 L7: warn when cors_allow_credentials=True meets wildcard origin.

    Browsers refuse the response per the CORS spec; logging at startup
    catches the misconfig before it reaches a real user.
    """

    def test_wildcard_with_credentials_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            cors_allowed_origins=("*",),
            cors_allow_credentials=True,
        )
        with caplog.at_level(logging.WARNING, logger="signet.server"):
            SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        # The warning fires once at startup.
        warnings = [
            r for r in caplog.records
            if "cors_allow_credentials" in r.getMessage()
            and "*" in r.getMessage()
        ]
        assert len(warnings) >= 1

    def test_specific_origins_with_credentials_no_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            cors_allowed_origins=("https://example.com",),
            cors_allow_credentials=True,
        )
        with caplog.at_level(logging.WARNING, logger="signet.server"):
            SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        # No CORS misconfig warning emitted.
        warnings = [
            r for r in caplog.records
            if "cors_allow_credentials" in r.getMessage()
        ]
        assert len(warnings) == 0


class TestBoolEnvParser:
    """v0.1.7 H4: ``_parse_bool_env`` accepts the spectrum of truthy values.

    CHANGELOG documented ``SIGNET_SHADOW=1`` but the original parser
    only accepted ``"true"``. Standardize so every bool-flag env var
    has identical semantics.
    """

    def test_truthy_values(self) -> None:
        from signet.server.config import _parse_bool_env

        for v in ("1", "true", "True", "TRUE", "yes", "YES", "on", " on ", "enabled"):
            assert _parse_bool_env(v) is True, f"expected truthy: {v!r}"

    def test_falsy_values(self) -> None:
        from signet.server.config import _parse_bool_env

        for v in ("0", "false", "FALSE", "no", "off", "", "  ", "disabled"):
            assert _parse_bool_env(v) is False, f"expected falsy: {v!r}"

    def test_shadow_accepts_one(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_SHADOW": "1"})
        assert cfg.shadow is True

    def test_shadow_accepts_yes(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_SHADOW": "yes"})
        assert cfg.shadow is True

    def test_emit_receipts_accepts_on(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_EMIT_RECEIPTS": "on"})
        assert cfg.emit_receipts is True

    def test_strict_redaction_accepts_uppercase(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_STRICT_ERROR_REDACTION": "TRUE"})
        assert cfg.strict_error_redaction is True

    def test_ephemeral_accepts_enabled(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_ALLOW_EPHEMERAL_KEY": "enabled"})
        assert cfg.allow_ephemeral_key is True

    def test_falsy_env_disables(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_SHADOW": "false"})
        assert cfg.shadow is False
        cfg = ServerConfig.from_env({"SIGNET_SHADOW": "0"})
        assert cfg.shadow is False
        cfg = ServerConfig.from_env({"SIGNET_SHADOW": "no"})
        assert cfg.shadow is False


class TestFromEnvErrorMessages:
    """v0.1.7 L8: ``from_env`` errors name the SIGNET_* var that failed.

    Bare ``int(value)`` / ``bytes.fromhex(value)`` raise ValueError with
    no context about which env var was bad. The wrapped parsers in
    ``config.py`` re-raise with the var name so misconfigurations are
    immediately attributable.
    """

    def test_bad_port_names_var(self) -> None:
        with pytest.raises(ValueError, match="SIGNET_PORT"):
            ServerConfig.from_env({"SIGNET_PORT": "abc"})

    def test_bad_request_timeout_names_var(self) -> None:
        with pytest.raises(ValueError, match="SIGNET_REQUEST_TIMEOUT_S"):
            ServerConfig.from_env({"SIGNET_REQUEST_TIMEOUT_S": "not-a-float"})

    def test_bad_max_request_body_bytes_names_var(self) -> None:
        with pytest.raises(ValueError, match="SIGNET_MAX_REQUEST_BODY_BYTES"):
            ServerConfig.from_env({"SIGNET_MAX_REQUEST_BODY_BYTES": "huge"})

    def test_bad_hmac_secret_names_var(self) -> None:
        # Non-hex characters fail with a SIGNET_HMAC_SECRET-named error.
        with pytest.raises(ValueError, match="SIGNET_HMAC_SECRET"):
            ServerConfig.from_env({"SIGNET_HMAC_SECRET": "not-hex-zzz"})

    def test_good_int_still_parses(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_PORT": "9999"})
        assert cfg.port == 9999


class TestFromEnvCliOnlyVarsIgnored:
    """v0.1.7 M1: ``SIGNET_LOG_FORMAT`` and ``SIGNET_ANONYMIZE_SALT`` are
    CLI-time vars; ``from_env`` does not touch them. The docstring says
    so explicitly; this test pins the behavior so a future refactor
    that decides to read them must also update the doc.
    """

    def test_log_format_is_not_a_serverconfig_field(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_LOG_FORMAT": "json"})
        # No field named ``log_format``; the env var is silently
        # ignored by ServerConfig (it's consumed at the CLI surface).
        assert not hasattr(cfg, "log_format")

    def test_anonymize_salt_is_not_a_serverconfig_field(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_ANONYMIZE_SALT": "deadbeef"})
        assert not hasattr(cfg, "anonymize_salt")


class TestInspectAllSseLines:
    """v0.1.7 S6: opt-in scanning of non-``data:`` SSE lines.

    By default INSPECTION only sees ``data:`` payloads — an upstream can
    smuggle content through ``event:`` / ``id:`` / ``retry:`` / ``:``
    lines. Flipping ``inspect_all_sse_lines=True`` feeds those payloads
    into ``ResponseContext.accumulated_text`` so checks like
    ScopeDriftCheck can scan them.
    """

    def test_default_does_not_extract_event_line(self) -> None:
        from signet.server.app import _extract_sse_content

        chunk = "event: foo\ndata: bar\n\n"
        # Default: only ``data:`` payloads contribute. ``bar`` is not
        # JSON so the JSON-parse path returns empty; ``foo`` is also
        # ignored.
        assert _extract_sse_content(chunk) == ""

    def test_inspect_all_lines_extracts_event_payload(self) -> None:
        from signet.server.app import _extract_sse_content

        chunk = "event: classified-marker (S//NF)\ndata: bar\n\n"
        out = _extract_sse_content(chunk, inspect_all_lines=True)
        # Event-line payload surfaces verbatim so scanners can match it.
        assert "(S//NF)" in out

    def test_inspect_all_lines_extracts_id_and_comment(self) -> None:
        from signet.server.app import _extract_sse_content

        chunk = (
            "id: 42-secret\n"
            ": comment-line (S//NF)\n"
            "retry: 5000\n"
            "data: {}\n"
            "\n"
        )
        out = _extract_sse_content(chunk, inspect_all_lines=True)
        assert "42-secret" in out
        assert "(S//NF)" in out
        assert "5000" in out

    def test_config_default_is_false(self) -> None:
        cfg = ServerConfig()
        assert cfg.inspect_all_sse_lines is False

    def test_config_env_parses(self) -> None:
        cfg = ServerConfig.from_env({"SIGNET_INSPECT_ALL_SSE_LINES": "1"})
        assert cfg.inspect_all_sse_lines is True

    def test_streaming_inspection_catches_event_line_marker(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """End-to-end: with the flag on, ScopeDriftCheck catches a
        marker that lives only on an ``event:`` line."""
        from signet.audit.backend import JsonlBackend
        from signet.checks.scope_drift import ScopeDriftCheck

        # Smuggled marker on the event line; the data: line is empty JSON.
        smuggled = (
            b"event: leak (S//NF) classified marker\n"
            b'data: {"choices":[{"delta":{"content":""}}]}\n'
            b"\n"
        )

        class _FakeResp:
            status_code = 200
            headers: ClassVar[dict[str, str]] = {"content-type": "text/event-stream"}

            async def aiter_bytes(self):
                yield smuggled

        class _FakeCM:
            async def __aenter__(self):
                return _FakeResp()

            async def __aexit__(self, *_a):
                return None

        def fake_stream(_self, _method, _url, **_kwargs):
            return _FakeCM()

        monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)

        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            inspect_all_sse_lines=True,
            strict_error_redaction=False,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(checks=[ScopeDriftCheck()]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={
                "stream": True,
                "model": "test",
                "messages": [{"role": "user", "content": "go"}],
            },
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 200
        # An inspection abort row was written.
        entries = list(JsonlBackend(log).iter_entries())
        names = {e.check_name for e in entries}
        assert "pipeline.inspection" in names

    def test_streaming_default_does_not_catch_event_line(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """Control: with the flag OFF, the same smuggled marker is NOT
        inspected — confirms the side-channel exists in default mode and
        the flag is the only gate against it."""
        from signet.audit.backend import JsonlBackend
        from signet.checks.scope_drift import ScopeDriftCheck

        smuggled = (
            b"event: leak (S//NF) classified marker\n"
            b'data: {"choices":[{"delta":{"content":""}}]}\n'
            b"\n"
        )

        class _FakeResp:
            status_code = 200
            headers: ClassVar[dict[str, str]] = {"content-type": "text/event-stream"}

            async def aiter_bytes(self):
                yield smuggled

        class _FakeCM:
            async def __aenter__(self):
                return _FakeResp()

            async def __aexit__(self, *_a):
                return None

        def fake_stream(_self, _method, _url, **_kwargs):
            return _FakeCM()

        monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)

        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            inspect_all_sse_lines=False,  # default
            strict_error_redaction=False,
        )
        signet_app = SignetApp(
            config=cfg,
            pipeline=Pipeline(checks=[ScopeDriftCheck()]),
        )
        client = TestClient(signet_app.app)
        r = client.post(
            "/v1/chat/completions",
            json={
                "stream": True,
                "model": "test",
                "messages": [{"role": "user", "content": "go"}],
            },
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 200
        # No inspection row was written — the marker on the event-line
        # was never seen by INSPECTION.
        entries = list(JsonlBackend(log).iter_entries())
        names = {e.check_name for e in entries}
        assert "pipeline.inspection" not in names


class TestAbortFrameKeyOrder:
    """v0.1.7 M4: abort frame field order matches the documented contract.

    docs/streaming.md documents ``signet_abort, reason, correlation_id,
    stage, check`` (in that order). SDKs parse JSON dicts unordered, but
    operators reading streamed log frames match by visual scan; the
    wire payload should match the doc.
    """

    @staticmethod
    def _build_app(strict: bool) -> Any:
        cfg = ServerConfig(
            upstream_url="http://m/v1",
            allow_ephemeral_key=True,
            strict_error_redaction=strict,
        )
        return SignetApp(config=cfg, pipeline=Pipeline(checks=[]))

    def test_strict_policy_block_key_order(self) -> None:
        from signet.audit.chain import HmacChain
        from signet.audit.keyring import Key, KeyRing
        from signet.core.audit import AuditEntry, Decision
        from signet.core.owner import Owner

        ring = KeyRing(active=Key(key_id="k1", secret=b"x" * 32))
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
                decision=Decision.BLOCK,
                reason="r",
            )
        )

        app = self._build_app(strict=True)
        frames = app._build_abort_frames(
            reason="some policy reason",
            stage="inspection",
            check_name="scope_drift",
            entry=entry,
        )
        # The first frame is the abort payload; insertion order matches
        # the documented ordering. We use list(payload.keys()) because
        # Python 3.7+ preserves dict insertion order on the wire.
        body = frames[0].decode("utf-8").lstrip("data: ").strip()
        import json as _json

        payload = _json.loads(body)
        keys = list(payload.keys())
        # Strict drops ``check`` so the prefix is the documented first
        # four keys; nothing follows.
        assert keys == ["signet_abort", "reason", "correlation_id", "stage"]

    def test_verbose_policy_block_key_order(self) -> None:
        app = self._build_app(strict=False)
        frames = app._build_abort_frames(
            reason="some policy reason",
            stage="inspection",
            check_name="scope_drift",
            entry=None,
        )
        body = frames[0].decode("utf-8").lstrip("data: ").strip()
        import json as _json

        payload = _json.loads(body)
        keys = list(payload.keys())
        # Verbose: full documented order including ``check``.
        assert keys == [
            "signet_abort",
            "reason",
            "correlation_id",
            "stage",
            "check",
        ]

    def test_transport_reason_strict_key_order(self) -> None:
        app = self._build_app(strict=True)
        frames = app._build_abort_frames(
            reason="upstream_protocol_violation",
            stage="inspection",
            check_name=None,
            entry=None,
        )
        import json as _json

        payload = _json.loads(frames[0].decode("utf-8").lstrip("data: ").strip())
        keys = list(payload.keys())
        # Transport reason preserves order; check is omitted (no firing
        # check on a wire-state failure).
        assert keys == ["signet_abort", "reason", "correlation_id", "stage"]


class TestMethodNotAllowed:
    """v0.1.7 M8 / L5: wrong-method requests share a single signet shape.

    Pre-fix: GET on a registered POST endpoint hit the ``unsupported_v1``
    catch-all and returned a 404 ``{"error": "endpoint not implemented..."}``;
    HEAD returned 405 with empty body; OPTIONS returned 405 with the
    Starlette default ``{"detail": "Method Not Allowed"}``. Three
    different shapes for the same client error class.

    Post-fix: a single 405 exception handler emits
    ``{"error": "method not allowed", "endpoint": "<path>",
    "allowed_methods": [...]}`` for every wrong-method request to a
    registered endpoint.
    """

    @pytest.fixture
    def client(self, app_factory) -> TestClient:
        _, c = app_factory(Pipeline(checks=[]))
        return c

    def test_get_on_chat_completions_returns_405_signet_shape(
        self, client: TestClient
    ) -> None:
        r = client.get("/v1/chat/completions")
        assert r.status_code == 405
        body = r.json()
        assert body["error"] == "method not allowed"
        assert body["endpoint"] == "/v1/chat/completions"
        # The endpoint accepts POST.
        assert "POST" in body["allowed_methods"]
        # Allow header carries the same set so HTTP-RFC-aware clients
        # see the legal verbs.
        allow = r.headers.get("Allow", "")
        assert "POST" in allow

    def test_options_on_chat_completions_returns_405_signet_shape(
        self, client: TestClient
    ) -> None:
        r = client.options("/v1/chat/completions")
        assert r.status_code == 405
        body = r.json()
        # OPTIONS does not return Starlette's ``{"detail": ...}`` —
        # the unified shape preempts it.
        assert body["error"] == "method not allowed"
        assert "POST" in body["allowed_methods"]

    def test_put_on_completions_returns_405(self, client: TestClient) -> None:
        r = client.put("/v1/completions")
        assert r.status_code == 405
        body = r.json()
        assert body["error"] == "method not allowed"

    def test_head_on_chat_completions_returns_405(self, client: TestClient) -> None:
        # HEAD is a distinct method; framework returns 405 + Allow.
        r = client.head("/v1/chat/completions")
        assert r.status_code == 405
        # HEAD response body MAY be empty per RFC, but the Allow header
        # must still be set.
        allow = r.headers.get("Allow", "")
        assert "POST" in allow

    def test_post_on_unimplemented_endpoint_still_404s_with_legacy_shape(
        self, client: TestClient
    ) -> None:
        """The 405 unification does NOT swallow the legacy 404 catch-all
        for genuinely unimplemented endpoints — that's M8's contract."""
        r = client.post("/v1/audio/transcriptions", json={})
        assert r.status_code == 404
        body = r.json()
        assert "not implemented" in body["error"]


class TestRealtimeDisabledStub:
    """v0.1.7 R3: ``realtime_enabled=False`` registers a stub that closes
    1011 with a structured reason, instead of an empty disconnect.
    """

    def test_disabled_realtime_closes_with_1011_and_reason(self, tmp_path) -> None:
        from starlette.websockets import WebSocketDisconnect

        cfg = ServerConfig(
            upstream_url="http://m/v1",
            allow_ephemeral_key=True,
            realtime_enabled=False,
        )
        signet_app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(signet_app.app)

        with (
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect("/v1/realtime") as ws,
        ):
            # Server closes immediately with 1011; the receive call
            # surfaces the disconnect with the configured code.
            ws.receive_text()
        assert excinfo.value.code == 1011
        # The reason field is documented and stable so operators can
        # grep for it in client logs.
        # WebSocket close.reason is exposed via the disconnect payload.
        # Starlette TestClient exposes it on the exception when set.
        assert "realtime endpoint disabled" in (excinfo.value.reason or "")
