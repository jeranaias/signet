"""Round 9 hunt closures — regression coverage.

Closes the seven findings from Round 9:

STREAMING (P0):
- ``sse-cr-line-terminator-bypass``: spec-valid ``\\r\\r`` / ``\\n\\r``
  / ``\\r\\n\\r`` / ``\\r\\r\\n`` / ``\\r\\n\\n`` / ``\\n\\r\\n``
  event terminators are now recognized by the outer raw-byte split.
- ``sse-unparseable-json-event-leaks-raw-bytes``: an event whose
  joined ``data:`` payload fails JSON parse now aborts the stream
  via ``upstream_sse_malformed`` rather than forwarding the raw bytes.
- ``sse-pending-raw-unbounded``: ``ctx.scratch["_pending_raw_sse"]``
  is now capped at :data:`signet.server.app._MAX_PENDING_RAW_SSE_BYTES`
  (4 MiB). Hitting the cap aborts via ``upstream_sse_unterminated``.

STREAMING (HIGH):
- ``sse-delta-fields-default-allow``: text-bearing fields under
  ``delta.*`` (e.g. ``thinking``, ``audio.text``,
  ``private_reasoning``) are now inspected by default. The pre-fix
  fixed allowlist (``content`` / ``refusal`` / ``reasoning`` /
  ``reasoning_content`` / ``audio.transcript``) was replaced with a
  default-deny recursive walk.
- ``sse-non-data-fields-default-skip``: ``inspect_all_sse_lines``
  defaults to ``True`` so ``retry:`` / ``event:`` / ``id:`` content
  is inspected without the operator having to opt in.

STREAMING (MED):
- ``sse-tool-call-function-description-uninspected``: tool-call
  metadata beyond ``function.name`` / ``function.arguments`` (e.g.
  ``function.description``) is inspected by the same recursive walk.

SERVER (MED):
- ``413-oversize-body-skips-audit-and-correlation_id``: the 413
  refusal now routes through ``_record_preflight_refusal`` and
  ``_preflight_body``, writing an audit row with
  ``_refusal_kind="body_too_large"``, ``correlation_id`` in the
  response body, and an ``X-Signet-Upstream`` attribution header.

SERVER (LOW):
- ``preflight-error-label-inconsistency``: the strict/verbose
  ``error`` field is now a stable snake_case token from a closed
  enumerated set; the human-readable text moved to
  ``verbose_extras.description``.
- ``upstream_url-config-accepts-arbitrary-schemes``:
  :class:`ServerConfig.__post_init__` rejects non-HTTP(S) schemes
  with a :class:`ValueError` at boot.

CROSS-DOMAIN:
- ``realtime-ws-admission-no-session-caps``: the realtime WebSocket
  admission preamble applies the same ``_MAX_SESSION_ID_BYTES`` /
  ``_SESSION_ID_RE`` caps the unary HTTP path enforces. Oversize /
  invalid-charset session IDs close the WS with code 1008 and write
  an audit row.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signet.audit.backend import JsonlBackend
from signet.checks.regex_content import Pattern, RegexOutputCheck
from signet.checks.scope_drift import ScopeDriftCheck
from signet.core.pipeline import Pipeline
from signet.server.app import (
    _MAX_PENDING_RAW_SSE_BYTES,
    _MAX_SESSION_ID_BYTES,
    SignetApp,
)
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Streaming attack scaffolding
# ---------------------------------------------------------------------------


def _install_fake_stream(monkeypatch: pytest.MonkeyPatch, chunks: list[bytes]) -> None:
    class _Resp:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):
            for c in chunks:
                yield c

    class _CM:
        async def __aenter__(self):
            return _Resp()

        async def __aexit__(self, *_a):
            return None

    def fake_stream(_self, _method, _url, **_kw):
        return _CM()

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


def _build_streaming_app(
    tmp_path: Path,
    *,
    checks: list[Any] | None = None,
    inspect_all_sse_lines: bool = True,
    strict_error_redaction: bool = False,
) -> tuple[SignetApp, TestClient, Path]:
    log = tmp_path / "audit.jsonl"
    cfg = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=log,
        inspect_all_sse_lines=inspect_all_sse_lines,
        strict_error_redaction=strict_error_redaction,
    )
    app = SignetApp(
        config=cfg,
        pipeline=Pipeline(checks=list(checks) if checks else []),
    )
    return app, TestClient(app.app), log


def _post_stream(client: TestClient) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        json={
            "stream": True,
            "model": "test",
            "messages": [{"role": "user", "content": "go"}],
        },
        headers={"X-Classification": "UNCLASS"},
    )


def _audit_rows(log: Path) -> list[Any]:
    if not log.exists():
        return []
    return list(JsonlBackend(log).iter_entries())


def _has_abort(body: str) -> bool:
    return "signet_abort" in body


# ---------------------------------------------------------------------------
# P0 -- sse-cr-line-terminator-bypass
# ---------------------------------------------------------------------------


class TestSseCrTerminatorBypass:
    @pytest.mark.parametrize(
        ("term", "label"),
        [
            (b"\r\r", "cr_cr"),
            (b"\n\r", "lf_cr"),
            (b"\r\n\r", "crlf_cr"),
            (b"\r\r\n", "cr_crlf"),
            (b"\r\n\n", "crlf_lf"),
            (b"\n\r\n", "lf_crlf"),
        ],
    )
    def test_cr_terminator_does_not_leak_marker(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, term: bytes, label: str
    ) -> None:
        # Spec-valid two-terminator pair. Marker must be inspected.
        # Use a strict-redaction pipeline so the abort frame's
        # ``reason`` field doesn't echo the offending marker text
        # (verbose-mode reasons quote the matched substring for
        # operator triage; strict mode coarsens to ``"refused"``).
        chunks = [
            b'data: {"choices":[{"delta":{"content":"hello (S//NF) leak"}}]}' + term,
            b"data: [DONE]" + term,
        ]
        _install_fake_stream(monkeypatch, chunks)
        pattern = Pattern(pattern=r"\(S//NF\)", action="block", label="classified")
        _app, client, log = _build_streaming_app(
            tmp_path,
            checks=[ScopeDriftCheck(), RegexOutputCheck([pattern])],
            strict_error_redaction=True,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        # Strict mode coarsens the abort reason; the original
        # upstream chunk (with the marker) must NOT reach the client.
        assert "(S//NF)" not in r.text, (
            f"{label}: marker leaked through {term!r} terminator: {r.text!r}"
        )
        assert "hello" not in r.text, f"{label}: upstream content bytes leaked: {r.text!r}"
        assert _has_abort(r.text), f"{label}: abort frame missing"
        names = {row.check_name for row in _audit_rows(log)}
        assert "pipeline.inspection" in names or "pipeline.upstream" in names, (
            f"{label}: no block audit row"
        )


# ---------------------------------------------------------------------------
# P0 -- sse-unparseable-json-event-leaks-raw-bytes
# ---------------------------------------------------------------------------


class TestSseMalformedEventAbort:
    def test_marker_in_first_data_line_blocked_by_multi_data_smuggle(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Pre-Round-9 attack: valid JSON ``data:`` line carries the
        # marker; appended garbage ``data:`` line breaks the joined
        # JSON parse; ``_flush_event`` drops the frame and the raw
        # bytes (with the marker) get forwarded. Post-fix: the parse
        # failure aborts the stream with ``upstream_sse_malformed``.
        chunks = [
            (
                b'data: {"choices":[{"delta":{"content":"hello (S//NF) leak"}}]}\n'
                b"data: garbage_breaks_json\n\n"
                b"data: [DONE]\n\n"
            ),
        ]
        _install_fake_stream(monkeypatch, chunks)
        _app, client, log = _build_streaming_app(tmp_path)
        r = _post_stream(client)
        assert r.status_code == 200
        assert "(S//NF)" not in r.text, (
            f"smuggled marker leaked through malformed-JSON event: {r.text!r}"
        )
        assert _has_abort(r.text)
        assert "upstream_sse_malformed" in r.text
        upstream_rows = [row for row in _audit_rows(log) if row.check_name == "pipeline.upstream"]
        assert upstream_rows, "no pipeline.upstream audit row written"


# ---------------------------------------------------------------------------
# P0 -- sse-pending-raw-unbounded
# ---------------------------------------------------------------------------


class TestSsePendingRawCap:
    def test_unterminated_stream_aborts_at_cap(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Build chunks that each fit under the 1 MiB per-chunk cap
        # but collectively exceed the 4 MiB pending-raw cap with no
        # terminator. The proxy must abort before buffering everything.
        chunk_size = 500_000  # 500 KB
        chunks = [
            b'data: {"choices":[{"delta":{"content":"' + b"A" * chunk_size,
        ]
        # 20 chunks * 500 KB = 10 MB total — well above the 4 MiB cap.
        for _ in range(19):
            chunks.append(b"A" * chunk_size)
        _install_fake_stream(monkeypatch, chunks)
        _app, client, log = _build_streaming_app(tmp_path)
        r = _post_stream(client)
        assert r.status_code == 200
        # Client body is the abort frame only; the buffered bytes
        # never leak.
        assert len(r.text) < 1024, f"pending-raw cap did not fire — got {len(r.text)} byte response"
        assert "upstream_sse_unterminated" in r.text
        upstream_rows = [row for row in _audit_rows(log) if row.check_name == "pipeline.upstream"]
        assert upstream_rows, "no pipeline.upstream row written"
        reason_detail = upstream_rows[-1].reason
        assert "pending-raw" in reason_detail
        assert str(_MAX_PENDING_RAW_SSE_BYTES) in reason_detail


# ---------------------------------------------------------------------------
# HIGH -- sse-delta-fields-default-allow
# ---------------------------------------------------------------------------


class TestSseDeltaDefaultDeny:
    @pytest.mark.parametrize(
        "delta",
        [
            {"thinking": "hello (S//NF) leak"},
            {"audio": {"text": "hello (S//NF) leak"}},
            {"private_reasoning": "hello (S//NF) leak"},
            {"content": "fine", "thinking": "hello (S//NF) leak"},
        ],
        ids=["thinking", "audio_text", "private_reasoning", "content_plus_thinking"],
    )
    def test_marker_in_non_allowlisted_field_blocked(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        delta: dict[str, Any],
    ) -> None:
        payload = json.dumps({"choices": [{"delta": delta}]}).encode()
        chunks = [
            b"data: " + payload + b"\n\n",
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        pattern = Pattern(pattern=r"\(S//NF\)", action="block", label="classified")
        _app, client, audit_log = _build_streaming_app(
            tmp_path, checks=[ScopeDriftCheck(), RegexOutputCheck([pattern])]
        )
        r = _post_stream(client)
        assert r.status_code == 200
        assert _has_abort(r.text), f"marker under default-deny delta field not blocked: {r.text!r}"
        # The block-stage audit row was written.
        rows = _audit_rows(audit_log)
        inspection_rows = [row for row in rows if row.check_name == "pipeline.inspection"]
        assert inspection_rows, f"no inspection row; rows={[r.check_name for r in rows]}"


class TestSseToolCallDefaultDeny:
    def test_tool_call_function_description_inspected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        payload = json.dumps(
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "do_thing",
                                        "description": "hello (S//NF) leak",
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        ).encode()
        chunks = [b"data: " + payload + b"\n\n", b"data: [DONE]\n\n"]
        _install_fake_stream(monkeypatch, chunks)
        pattern = Pattern(pattern=r"\(S//NF\)", action="block", label="classified")
        _app, client, _log = _build_streaming_app(
            tmp_path, checks=[ScopeDriftCheck(), RegexOutputCheck([pattern])]
        )
        r = _post_stream(client)
        assert r.status_code == 200
        assert _has_abort(r.text), (
            f"marker in tool_calls[0].function.description leaked: {r.text!r}"
        )


# ---------------------------------------------------------------------------
# HIGH -- sse-non-data-fields-default-skip (default flipped to True)
# ---------------------------------------------------------------------------


class TestInspectAllSseLinesDefault:
    def test_default_flag_is_true(self) -> None:
        cfg = ServerConfig()
        assert cfg.inspect_all_sse_lines is True

    def test_marker_in_event_line_blocked_by_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        chunks = [
            b"event: (S//NF) classified marker\n"
            b'data: {"choices":[{"delta":{"content":"benign"}}]}\n\n',
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        # Use default config -- flag is now True.
        _app, client, _audit_log = _build_streaming_app(tmp_path, checks=[ScopeDriftCheck()])
        r = _post_stream(client)
        assert r.status_code == 200
        assert "(S//NF)" not in r.text or _has_abort(r.text), (
            f"marker on event: line leaked: {r.text!r}"
        )


# ---------------------------------------------------------------------------
# SERVER MED -- 413-oversize-body-skips-audit-and-correlation_id
# ---------------------------------------------------------------------------


class TestBodyTooLargeAuditRow:
    def test_413_writes_audit_row_with_correlation_id(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            max_request_body_bytes=100,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post("/v1/chat/completions", content=b"x" * 500)
        assert r.status_code == 413
        body = r.json()
        # Stable token + correlation_id (strict mode).
        assert body["error"] == "body_too_large"
        assert body["correlation_id"] is not None
        # Attribution header now present (was missing pre-Round-9).
        assert r.headers.get("X-Signet-Upstream")
        # Audit row written.
        rows = _audit_rows(log)
        preflight = [row for row in rows if row.check_name == "pipeline.preflight"]
        assert len(preflight) == 1
        assert preflight[0].metadata.get("_refusal_kind") == "body_too_large"
        # Correlation_id in body matches the audit row.
        assert body["correlation_id"] == preflight[0].entry_id

    def test_413_verbose_mode_keeps_limit_and_description(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            max_request_body_bytes=100,
            strict_error_redaction=False,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post("/v1/chat/completions", content=b"x" * 500)
        assert r.status_code == 413
        body = r.json()
        assert body["error"] == "body_too_large"
        assert body["limit_bytes"] == 100
        assert "description" in body
        assert body["bytes_seen"] >= 100


# ---------------------------------------------------------------------------
# SERVER LOW -- preflight-error-label-inconsistency
# ---------------------------------------------------------------------------


class TestPreflightErrorTokens:
    """Every preflight refusal's ``error`` field is now a stable
    snake_case token from a closed enumerated set."""

    _PREFLIGHT_TOKENS: ClassVar[frozenset[str]] = frozenset(
        {
            "empty_body",
            "json_decode_error",
            "invalid_encoding",
            "non_object_body",
            "non_finite_float",
            "session_id_too_long",
            "session_id_invalid_charset",
            "body_too_large",
            # Round 11 ``json_too_deeply_nested-envelope-shape-
            # inconsistency`` closure: the legacy ``{"signet": ...}``
            # envelope was flattened to match peers, so this token is
            # now part of the closed enum.
            "json_too_deeply_nested",
        }
    )

    @pytest.mark.parametrize(
        ("body_bytes", "expected_token"),
        [
            (b"", "empty_body"),
            (b"this is not json", "json_decode_error"),
            (b"[]", "non_object_body"),
            (b"123", "non_object_body"),
            (b"null", "non_object_body"),
            (
                b'{"messages":[], "temperature": NaN}',
                "non_finite_float",
            ),
            (bytes([0xFF, 0xFE, 0xFD]), "invalid_encoding"),
        ],
    )
    def test_strict_mode_error_field_is_stable_token(
        self, tmp_path: Path, body_bytes: bytes, expected_token: str
    ) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            content=body_bytes,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] in self._PREFLIGHT_TOKENS
        assert body["error"] == expected_token


# ---------------------------------------------------------------------------
# SERVER LOW -- upstream_url-config-accepts-arbitrary-schemes
# ---------------------------------------------------------------------------


class TestUpstreamUrlSchemeValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://x",
            "gopher://x",
            "data:text/plain,x",
            "ws://localhost/realtime",
        ],
    )
    def test_non_http_scheme_rejected(self, url: str) -> None:
        with pytest.raises(ValueError, match="http://"):
            ServerConfig(
                upstream_url=url,
                hmac_secret=b"\x00" * 32,
                allow_ephemeral_key=False,
            )

    def test_http_scheme_accepted(self) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
        )
        assert cfg.upstream_url == "http://upstream-mock/v1"

    def test_https_scheme_accepted(self) -> None:
        cfg = ServerConfig(
            upstream_url="https://api.openai.com/v1",
            allow_ephemeral_key=True,
        )
        assert cfg.upstream_url == "https://api.openai.com/v1"

    def test_from_env_rejects_bad_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValueError, match="http://"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "file:///etc/passwd",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )


# ---------------------------------------------------------------------------
# CROSS-DOMAIN -- realtime-ws-admission-no-session-caps
# ---------------------------------------------------------------------------


class TestRealtimeSessionIdCaps:
    def _build(self, tmp_path: Path) -> tuple[TestClient, Path]:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=False,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        return TestClient(app.app), log

    def test_oversize_session_id_closes_with_1008(self, tmp_path: Path) -> None:
        client, log = self._build(tmp_path)
        sid = "A" * (_MAX_SESSION_ID_BYTES + 1)
        seen_code: int | None = None
        with client.websocket_connect("/v1/realtime", headers={"X-Signet-Session": sid}) as ws:
            # Read the synthetic refusal event before close.
            event = ws.receive_json()
            assert event["type"] == "signet.refusal"
            assert event["stage"] == "admission"
            try:
                ws.receive_json()
            except WebSocketDisconnect as exc:
                seen_code = exc.code
        assert seen_code == 1008
        rows = _audit_rows(log)
        admit_rows = [row for row in rows if row.check_name == "pipeline.admission"]
        assert admit_rows
        kinds = {row.metadata.get("_refusal_kind") for row in admit_rows}
        assert "session_id_too_long" in kinds

    def test_invalid_charset_session_id_closes_with_1008(self, tmp_path: Path) -> None:
        client, log = self._build(tmp_path)
        seen_code: int | None = None
        with client.websocket_connect(
            "/v1/realtime", headers={"X-Signet-Session": "abc\x00def"}
        ) as ws:
            event = ws.receive_json()
            assert event["type"] == "signet.refusal"
            try:
                ws.receive_json()
            except WebSocketDisconnect as exc:
                seen_code = exc.code
        assert seen_code == 1008
        rows = _audit_rows(log)
        admit_rows = [row for row in rows if row.check_name == "pipeline.admission"]
        assert admit_rows
        kinds = {row.metadata.get("_refusal_kind") for row in admit_rows}
        assert "session_id_invalid_charset" in kinds
        # The audit row must NOT echo the offending value (it may
        # contain NULs).
        for row in admit_rows:
            row_json = json.dumps(row.metadata)
            assert "\x00" not in row_json
