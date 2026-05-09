"""N3 round-trip integration: --upstream-label / SIGNET_UPSTREAM_LABEL
flows through to the X-Signet-Upstream response header on every
successful and refused response.

Catches drift between the CLI/config field and the header builder.
The flag was added in v0.1.4 but never had a round-trip test —
silent regression risk during refactor. This locks in:

* allowed (200) responses carry X-Signet-Upstream = configured label
* refusals (403) carry X-Signet-Upstream = configured label
* upstream_label=None falls back to the upstream_url netloc
* /health, /healthz, /readyz, /version are signet's own endpoints
  and intentionally do NOT carry X-Signet-Upstream
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.checks import OwnerResolutionCheck
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig


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
def label_app_factory(
    monkeypatch: pytest.MonkeyPatch, upstream_response_body: dict[str, Any]
):
    """Build a SignetApp + TestClient with a caller-supplied ServerConfig.

    Mirrors ``app_factory`` in test_server_app.py but lets the caller
    construct the ServerConfig so each test can pin upstream_label /
    upstream_url to whatever shape it needs.
    """

    def _make(
        pipeline: Pipeline, config: ServerConfig
    ) -> tuple[SignetApp, TestClient]:
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
        signet_app = SignetApp(config=config, pipeline=pipeline)
        return signet_app, TestClient(signet_app.app)

    return _make


class TestUpstreamLabel:
    """End-to-end: ServerConfig.upstream_label -> X-Signet-Upstream."""

    def test_label_appears_on_successful_response(self, label_app_factory) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            upstream_label="thornveil-prod",
            allow_ephemeral_key=True,
            strict_error_redaction=False,
        )
        _, client = label_app_factory(
            Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            config,
        )
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        assert r.headers.get("X-Signet-Upstream") == "thornveil-prod"

    def test_label_appears_on_refusal_response(self, label_app_factory) -> None:
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            upstream_label="thornveil-prod",
            allow_ephemeral_key=True,
            strict_error_redaction=False,
        )
        # No X-Commit-Owner header -> OwnerResolutionCheck refuses.
        _, client = label_app_factory(
            Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            config,
        )
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 403
        # Refusals never reach upstream, but the gate-of-record header
        # still fires so callers know which signet was the gate.
        assert r.headers.get("X-Signet-Upstream") == "thornveil-prod"

    def test_no_label_falls_back_to_url_host(self, label_app_factory) -> None:
        # upstream_label=None -> X-Signet-Upstream should be the netloc
        # of upstream_url. Use a host:port URL so we exercise both parts.
        config = ServerConfig(
            upstream_url="http://upstream.example.com:8443/v1",
            upstream_label=None,
            allow_ephemeral_key=True,
            strict_error_redaction=False,
        )
        _, client = label_app_factory(
            Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            config,
        )
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Commit-Owner": "human:alice"},
        )
        assert r.status_code == 200
        assert r.headers.get("X-Signet-Upstream") == "upstream.example.com:8443"

    def test_health_endpoints_omit_label(self, label_app_factory) -> None:
        # /health, /healthz, /version are signet's own endpoints, not
        # upstream forwards. The current header builder only fires from
        # _upstream_attribution_headers (proxy + refusal + escalation
        # paths), so these endpoints intentionally do NOT carry the
        # header. Lock in that behavior so a future "always set it"
        # refactor has to consciously reverse this test.
        config = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            upstream_label="thornveil-prod",
            allow_ephemeral_key=True,
        )
        _, client = label_app_factory(Pipeline(checks=[]), config)

        for path in ("/health", "/healthz", "/version"):
            r = client.get(path)
            assert r.status_code == 200, f"{path} returned {r.status_code}"
            assert "X-Signet-Upstream" not in r.headers, (
                f"{path} unexpectedly carried X-Signet-Upstream"
            )

    def test_readyz_unreachable_omits_label(self, label_app_factory) -> None:
        # /readyz with an unreachable upstream returns 503 with a JSON
        # body that *includes* the label inside the body (config
        # behavior), but does NOT set the X-Signet-Upstream response
        # header — same rationale as /health: it's a signet endpoint,
        # not an upstream proxy.
        config = ServerConfig(
            upstream_url="http://upstream-mock-unreachable/v1",
            upstream_label="thornveil-prod",
            allow_ephemeral_key=True,
        )
        _, client = label_app_factory(Pipeline(checks=[]), config)

        r = client.get("/readyz")
        assert r.status_code == 503
        assert "X-Signet-Upstream" not in r.headers
        # Sanity: label still surfaces in the JSON body, which is the
        # documented operator-facing signal for /readyz.
        assert r.json().get("upstream") == "thornveil-prod"
