"""Integration regression test for Round 4 hunt -- sync-path 3xx block.

The unit-tier coverage (``tests/unit/test_round4_hunt.py``) drives the
forward methods directly with patched httpx clients. This file pins the
end-to-end wire shape so an audit consumer and an SDK can both rely on
the contract: structured 502 body, attribution headers, ``signet``
object with the documented keys, audit chain row, and no upstream
Location URL leakage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.checks import OwnerResolutionCheck
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig


def _build_app(tmp_path: Path) -> tuple[Path, TestClient]:
    log = tmp_path / "audit.jsonl"
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        upstream_label="test-upstream",
        allow_ephemeral_key=True,
        audit_log_path=log,
        strict_error_redaction=False,
    )
    app = SignetApp(
        config=config,
        pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
    )
    return log, TestClient(app.app)


def _read_entries(log: Path) -> list[Any]:
    if not log.exists():
        return []
    return list(JsonlBackend(log).iter_entries())


def test_round4_sync_3xx_blocked_e2e(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end: a 302 upstream response must produce a signet-shaped
    502, an audit row, and zero raw Location URL leakage.

    Wire contract pinned here:

    * ``r.status_code == 502``
    * ``r.json() == {"signet": {"error": "upstream_redirected",
      "upstream_status": 302, "upstream_location_host": "<host>",
      "correlation_id": "<id>"}}`` (the correlation_id is added by the
      shared helper when the audit chain wrote a row).
    * No path / query / fragment / userinfo from the Location header
      appears in the response.
    * Exactly one ``pipeline.upstream`` audit row with
      ``_refusal_kind=upstream_redirect``.
    """

    async def fake_post(_self, _url, **_kwargs):
        class FakeResp:
            status_code = 302
            content = b"<html>moved</html>"
            headers: ClassVar[dict[str, str]] = {
                "content-type": "text/html",
                "location": "https://hostile.example.com/auth?next=/x#frag",
            }

            @staticmethod
            def json() -> dict[str, Any]:
                import json as _json

                raise _json.JSONDecodeError("redirect body", "doc", 0)

        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path)

    r = client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-Commit-Owner": "human:alice"},
    )

    assert r.status_code == 502
    body = r.json()
    assert "signet" in body
    sig = body["signet"]
    assert sig["error"] == "upstream_redirected"
    assert sig["upstream_status"] == 302
    assert sig["upstream_location_host"] == "hostile.example.com"
    assert sig["correlation_id"]
    # Closed-set on the ``signet`` keys to guard against future leakage.
    assert set(sig.keys()) == {
        "error",
        "upstream_status",
        "upstream_location_host",
        "correlation_id",
    }
    # The Location URL components MUST NOT appear anywhere in the body.
    for forbidden in ("/auth", "next=/x", "frag", "<html>", "moved"):
        assert forbidden not in r.text

    # Attribution headers still fire.
    assert r.headers.get("X-Signet-Upstream") == "test-upstream"
    assert r.headers.get("X-Signet-Upstream-Status") == "302"

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    row = rows[0]
    assert row.decision.value == "block"
    assert row.metadata["_refusal_kind"] == "upstream_redirect"
    assert row.metadata["upstream_status"] == 302
    assert row.metadata["upstream_location_host"] == "hostile.example.com"
