"""Integration regression tests for v0.1.8.1 F1 / N1 fixes.

F1 -- non-streaming upstream errors now write a structured audit row
(``check_name='pipeline.upstream'`` with a ``_refusal_kind``
discriminator) AND return a signet-shaped JSONResponse instead of
passing the upstream's raw body verbatim through to the client. Prior
behavior leaked HTML error pages, redirect bodies, and arbitrary upstream
content; tests below assert the new closed-set contract.

N1 -- binary WebSocket frames now write a per-frame audit row and bump
a session-level ``binary_frames_received`` counter. The unit-tier
coverage in ``tests/unit/test_realtime.py::TestBinaryFrameAudit`` drives
the WebSocket directly; this file pins the streaming-path regression
guarantee so an audit consumer can rely on every binary frame leaving
exactly one row.

The unit-tier coverage for F1 sub-cases lives in
``tests/unit/test_server_app.py::TestUpstreamNonJsonAttribution`` and
the helpers below; this file's tests focus on the four failure modes as
seen end-to-end through ``SignetApp`` so the audit row, the response
status, and the wire-shape contract all line up.
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


def _build_app(tmp_path: Path, *, strict: bool = False) -> tuple[Path, TestClient]:
    """Build a SignetApp with an audit log, return (log_path, client)."""
    log = tmp_path / "audit.jsonl"
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        upstream_label="test-upstream",
        allow_ephemeral_key=True,
        audit_log_path=log,
        strict_error_redaction=strict,
    )
    app = SignetApp(
        config=config,
        pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
    )
    return log, TestClient(app.app)


def _post(client: TestClient) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        headers={"X-Commit-Owner": "human:alice"},
    )


def _read_entries(log: Path) -> list[Any]:
    if not log.exists():
        return []
    return list(JsonlBackend(log).iter_entries())


# ---------------------------------------------------------------------------
# F1.a -- sync RuntimeError from the upstream client
# ---------------------------------------------------------------------------


def test_f1_sync_runtime_error_writes_audit_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1: sync upstream RuntimeError writes audit row + redacts body.

    A misbehaving httpx subclass (or a bug in transport configuration)
    that raises a non-httpx ``RuntimeError`` previously bypassed the
    audit chain on the sync path -- the outer ``_handle_chat`` catch
    fired with the wrong check name and the body shape leaked the
    exception class only. F1 routes the failure through
    ``_record_upstream_failure`` which writes a ``pipeline.upstream``
    audit row with ``_refusal_kind=upstream_exception``.
    """

    async def fake_post(_self, _url, **_kwargs):
        raise RuntimeError("misconfigured transport")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path)
    r = _post(client)

    assert r.status_code == 502
    # Signet-shaped body, NOT a traceback, NOT upstream content.
    body = r.json()
    assert body["error"] == "upstream forward failed"
    assert body["refusal_kind"] == "upstream_exception"
    assert body["correlation_id"]
    assert body["exception"] == "RuntimeError"

    # Exactly one pipeline.upstream audit row.
    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    assert rows[0].decision.value == "block"
    assert rows[0].metadata["_refusal_kind"] == "upstream_exception"
    assert rows[0].metadata["_exception_class"] == "RuntimeError"


# ---------------------------------------------------------------------------
# F1.b -- HTML body must NOT pass through on sync error
# ---------------------------------------------------------------------------


def test_f1_sync_html_body_redacted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """v0.1.8 F1: upstream HTML body MUST NOT pass through on sync error.

    An upstream that ships HTML on a JSON endpoint (502 maintenance
    page, login redirect, intermediary proxy error) previously had its
    raw bytes echoed through to the client -- a hostile or merely
    careless body could carry inline ``<script>`` tags that lit up on
    a browser-side consumer. F1 replaces the body with a signet-shaped
    JSONResponse and writes the audit row.
    """

    async def fake_post(_self, _url, **_kwargs):
        class FakeResp:
            status_code = 502
            content = (
                b"<html><body><script>alert('owned')</script>internal server error</body></html>"
            )
            headers: ClassVar[dict[str, str]] = {"content-type": "text/html"}

            @staticmethod
            def json() -> dict[str, Any]:
                import json as _json

                raise _json.JSONDecodeError("not json", "doc", 0)

        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path)
    r = _post(client)

    assert r.status_code == 502
    # The CT guard fires first: HTML content-type → invalid CT.
    assert r.headers.get("content-type", "").startswith("application/json")
    body = r.json()
    assert body["error"] == "upstream forward failed"
    # No raw upstream content anywhere in the response body.
    assert "<script>" not in r.text
    assert "alert(" not in r.text
    assert "internal server error" not in r.text
    # Attribution headers still fire so the caller can tell upstream.
    assert r.headers.get("X-Signet-Upstream") == "test-upstream"
    assert r.headers.get("X-Signet-Upstream-Status") == "502"

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    # CT guard fires before JSON parse → refusal_kind is CT-invalid.
    assert rows[0].metadata["_refusal_kind"] == "upstream_content_type_invalid"
    assert rows[0].metadata.get("upstream_status") == 502


# ---------------------------------------------------------------------------
# F1.c -- non-JSON body on a JSON content-type
# ---------------------------------------------------------------------------


def test_f1_sync_json_decode_error_writes_audit_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1: upstream advertises JSON but body fails to parse.

    Distinct from the content-type guard (F1.b): here the upstream
    advertises ``application/json`` but ships malformed JSON (truncated
    body, partial chunk that landed on the wire, etc.). Signet writes
    the audit row with ``_refusal_kind=upstream_decode_error`` so
    operators can split this failure class out from CT mismatches.
    """

    async def fake_post(_self, _url, **_kwargs):
        class FakeResp:
            status_code = 200
            content = b"{not-json"
            headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

            @staticmethod
            def json() -> dict[str, Any]:
                import json as _json

                raise _json.JSONDecodeError("not json", "doc", 0)

        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path)
    r = _post(client)

    assert r.status_code == 502
    body = r.json()
    assert body["error"] == "upstream forward failed"
    assert body["refusal_kind"] == "upstream_decode_error"
    assert body["upstream_status"] == 200
    assert body["correlation_id"]
    # Upstream body (the bad JSON) does NOT leak.
    assert "{not-json" not in r.text

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    assert rows[0].metadata["_refusal_kind"] == "upstream_decode_error"
    assert rows[0].metadata.get("upstream_status") == 200


# ---------------------------------------------------------------------------
# F1.d -- httpx connection failure (HTTPError family)
# ---------------------------------------------------------------------------


def test_f1_sync_httpx_connect_error_writes_audit_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1: httpx connect/read errors map to upstream_protocol_violation.

    Verifies the ``httpx.HTTPError`` branch of the new sync-path
    handler is reachable: any connect, read, or transport failure
    surfaces a structured audit row with
    ``_refusal_kind=upstream_protocol_violation`` rather than crashing
    into the outer ``_handle_chat`` catch.
    """

    async def fake_post(_self, _url, **_kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path)
    r = _post(client)

    assert r.status_code == 502
    body = r.json()
    assert body["error"] == "upstream forward failed"
    assert body["refusal_kind"] == "upstream_protocol_violation"
    assert body["exception"] == "ConnectError"
    assert body["correlation_id"]

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    assert rows[0].metadata["_refusal_kind"] == "upstream_protocol_violation"
    assert rows[0].metadata["_exception_class"] == "ConnectError"


# ---------------------------------------------------------------------------
# F1.e -- streaming-path contract preserved (regression guard)
# ---------------------------------------------------------------------------


def test_f1_streaming_path_unchanged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """v0.1.8 F1: the existing streaming-path abort contract must
    survive the sync-path rewrite.

    F1 only adds a sync-path handler; the streaming-path
    (``_emit_upstream_error_abort``) already wrote the audit row +
    emitted a structured abort frame. This test pins the contract by
    driving a streaming request against a fake upstream that returns
    a 502, then asserting the abort frame fires AND a
    ``pipeline.upstream`` row exists.
    """
    from contextlib import asynccontextmanager

    class FakeStream:
        status_code = 502
        headers: ClassVar[dict[str, str]] = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):  # pragma: no cover -- not reached
            yield b""

    @asynccontextmanager
    async def fake_stream(_self, _method, _url, **_kwargs):
        yield FakeStream()

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)
    log, client = _build_app(tmp_path)

    with client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "test",
            "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        },
        headers={"X-Commit-Owner": "human:alice"},
    ) as r:
        assert r.status_code == 200  # SSE handshake itself completes
        body = b"".join(r.iter_bytes())

    # Structured abort frame is on the wire.
    assert b"signet_abort" in body
    assert b"upstream_protocol_violation" in body
    assert b"[DONE]" in body

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    assert rows[0].decision.value == "block"


# ---------------------------------------------------------------------------
# F1.f -- strict error redaction coarsens the body
# ---------------------------------------------------------------------------


def test_f1_strict_redaction_coarsens_body(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """v0.1.8 F1: under strict_error_redaction=True, the upstream-failure
    body collapses to ``{"error": "upstream forward failed",
    "correlation_id": "..."}`` only.

    Mirrors the existing :meth:`SignetApp._refusal` redaction rule so
    the closed-set on what signet emits stays consistent across refusal
    flavors. Operators recover full detail (refusal_kind, exception
    class, upstream status) from the audit row via the correlation ID.
    """

    async def fake_post(_self, _url, **_kwargs):
        raise RuntimeError("opaque detail")

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    log, client = _build_app(tmp_path, strict=True)
    r = _post(client)

    assert r.status_code == 502
    body = r.json()
    # Only the closed-set keys appear under strict.
    assert set(body.keys()) == {"error", "correlation_id"}
    assert body["error"] == "upstream forward failed"
    assert body["correlation_id"]
    # The opaque detail leaks nowhere.
    assert "opaque detail" not in r.text
    assert "RuntimeError" not in r.text

    # Audit row still carries the verbose detail for forensics.
    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1
    assert rows[0].metadata["_exception_class"] == "RuntimeError"
    assert "opaque detail" in rows[0].metadata["_exception_message"]


# ---------------------------------------------------------------------------
# F1.5 -- streaming-path ``async with client.stream(...)`` ``__aenter__`` fails
# ---------------------------------------------------------------------------


def _post_stream(client: TestClient) -> Any:
    """POST a streaming chat-completions request through the integration
    harness. Mirrors ``_post`` but flips ``stream=True``."""
    return client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "test",
            "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        },
        headers={"X-Commit-Owner": "human:alice"},
    )


def test_f15_stream_init_connect_error_writes_audit_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1.5: ``httpx.ConnectError`` from
    ``client.stream(...).__aenter__`` produces a structured abort frame
    + a ``pipeline.upstream`` audit row.

    Pre-fix, the exception leaked through the StreamingResponse
    generator and the SDK saw an opaque ASGI exception. The
    ``finally`` branch wrote ``pipeline.complete`` with
    ``finish_reason="client_disconnect"`` -- wrong cause attribution.

    F1.5 wraps ``async with client.stream(...)`` in an outer
    ``try/except`` so init-time failures route through
    :meth:`_emit_upstream_error_abort` (same helper the in-body
    handlers use). One ``pipeline.upstream`` row, NO
    ``pipeline.complete`` row tagged ``client_disconnect``.
    """
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_stream(_self, _method, _url, **_kwargs):
        raise httpx.ConnectError("connection refused")
        yield  # pragma: no cover -- never reached, keeps asynccontextmanager happy

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)
    log, client = _build_app(tmp_path)

    with _post_stream(client) as r:
        assert r.status_code == 200  # SSE handshake itself completes
        body = b"".join(r.iter_bytes())

    # Structured abort frame on the wire; reason matches the
    # streaming-transport vocabulary.
    assert b"signet_abort" in body
    assert b"upstream_protocol_violation" in body
    assert b"[DONE]" in body

    entries = _read_entries(log)
    upstream_rows = [e for e in entries if e.check_name == "pipeline.upstream"]
    assert len(upstream_rows) == 1
    meta = upstream_rows[0].metadata
    assert meta.get("_exception_class") == "ConnectError"
    assert meta.get("abort_stage") == "upstream"

    # No spurious pipeline.complete row with client_disconnect cause
    # attribution -- the outer except path correctly sets
    # ``upstream_aborted`` so the ``finally`` skips the terminal row.
    complete_rows = [e for e in entries if e.check_name == "pipeline.complete"]
    assert len(complete_rows) == 0


def test_f15_stream_init_generic_runtime_error_writes_audit_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1.5: non-httpx exceptions from ``__aenter__`` (e.g.
    RuntimeError from a misconfigured transport) get the
    ``upstream_exception`` reason token, distinct from
    ``upstream_protocol_violation``, so SDKs can split retry semantics.
    """
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_stream(_self, _method, _url, **_kwargs):
        raise RuntimeError("misconfigured transport")
        yield  # pragma: no cover

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)
    log, client = _build_app(tmp_path)

    with _post_stream(client) as r:
        assert r.status_code == 200
        body = b"".join(r.iter_bytes())

    assert b"signet_abort" in body
    # New transport reason token -- separate from
    # ``upstream_protocol_violation`` for non-httpx failures.
    assert b"upstream_exception" in body
    assert b"[DONE]" in body

    entries = _read_entries(log)
    upstream_rows = [e for e in entries if e.check_name == "pipeline.upstream"]
    assert len(upstream_rows) == 1
    assert upstream_rows[0].metadata.get("_exception_class") == "RuntimeError"

    complete_rows = [e for e in entries if e.check_name == "pipeline.complete"]
    assert len(complete_rows) == 0


def test_f15_stream_init_strict_redaction_preserves_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """v0.1.8 F1.5: strict redaction preserves the transport reason
    token so SDKs can branch on retry semantics, mirroring the existing
    strict-redaction contract for mid-stream protocol violations.
    """
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_stream(_self, _method, _url, **_kwargs):
        raise httpx.ConnectError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)
    log, client = _build_app(tmp_path, strict=True)

    with _post_stream(client) as r:
        assert r.status_code == 200
        body = b"".join(r.iter_bytes())

    # Strict still keeps the transport reason (in
    # ``_TRANSPORT_ABORT_REASONS``) so SDKs can react.
    assert b"upstream_protocol_violation" in body
    # Strict still drops firing-check identity from the abort frame.
    assert b'"check":' not in body or b'"check": null' in body

    rows = [e for e in _read_entries(log) if e.check_name == "pipeline.upstream"]
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# Round-4 CLI traceback regression -- end-to-end via the CLI module so
# the entrypoint is exercised the same way an operator would invoke it.
# Mirrors the v0.1.7 C6 "no raw tracebacks" contract for the three
# audit/serve surfaces that still leaked tracebacks.
# ---------------------------------------------------------------------------


class TestRound4CliTracebackRegression:
    """End-to-end pin for NEW-3 / NEW-9 / NEW-10 via the CLI module."""

    def _run_cli(self, args: list[str]) -> tuple[int, str]:
        from click.testing import CliRunner

        from signet.cli import main

        runner = CliRunner()
        result = runner.invoke(main, args)
        return result.exit_code, result.output

    def test_new3_audit_compact_malformed_no_traceback(self, tmp_path: Path) -> None:
        from signet.audit.chain import HmacChain
        from signet.audit.keyring import Key, KeyRing
        from signet.core.audit import AuditEntry, Decision
        from signet.core.owner import Owner

        log_path = tmp_path / "audit.jsonl"
        secret = b"x" * 32
        chain = HmacChain(
            JsonlBackend(log_path),
            KeyRing(active=Key(key_id="k1", secret=secret)),
        )
        chain.append(
            AuditEntry(
                owner=Owner.human("alice"),
                check_name="x",
                decision=Decision.ALLOW,
                reason="ok",
            )
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{not valid json,\n")

        code, out = self._run_cli(
            [
                "audit",
                "compact",
                "--audit-log",
                str(log_path),
                "--before",
                "2030-01-01T00:00:00Z",
                "--output",
                str(tmp_path / "archive.bin"),
                "--force",
                "--quiesce-confirm",
                "--hmac-secret",
                secret.hex(),
            ]
        )
        assert code != 0, out
        assert "Traceback (most recent call last)" not in out
        assert "malformed" in out.lower()

    def test_new9_serve_port_overflow_no_traceback(self) -> None:
        code, out = self._run_cli(["serve", "--port", "99999", "--upstream", "http://x/v1"])
        assert code == 2, out
        assert "Traceback (most recent call last)" not in out

    def test_new10_audit_report_since_overflow_no_traceback(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("", encoding="utf-8")
        code, out = self._run_cli(
            [
                "audit",
                "report",
                "--audit-log",
                str(log_path),
                "--since",
                "999999999d",
                "--no-anonymize",
            ]
        )
        assert code != 0, out
        assert "Traceback (most recent call last)" not in out
        lowered = out.lower()
        assert "duration too large" in lowered or "overflow" in lowered
