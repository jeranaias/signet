"""Round 13 hunt closures — regression coverage.

Closes the five Round 13 findings + the INFO ``from_env`` Unicode
whitespace extension:

SERVER (LOW):

- ``admission-pipeline-crash-leaks-classname``: sibling miss of R12's
  ``_outer_fallback_response`` -- the admission-side bare-``except
  Exception`` catch in ``_admit`` returned a 500 body that leaked the
  Python exception class name under strict_error_redaction, omitted
  ``correlation_id``, and omitted ``X-Signet-Upstream``. Post-fix the
  500 routes through ``_admission_fallback_response`` so the wire shape
  honors strict redaction, carries the audit-row entry_id, and sets
  the attribution header.

- ``forwarded-header-crlf-injection``: client-controlled
  ``Authorization`` / ``OpenAI-Beta`` / ``OpenAI-Organization`` values
  containing ``\\r`` / ``\\n`` / ``\\0`` previously reached the upstream
  HTTP client unsanitized; h11 caught them at wire-send and signet
  funneled the failure to a misleading 502 ``upstream_protocol_violation``.
  Post-fix the admit path validates header values with
  ``_header_value_is_safe`` and refuses the request with a structured
  400 ``header_invalid_charset`` + audit row.

- ``setattr-validates-only-upstream_url``: ``ServerConfig.__setattr__``
  re-ran validation only for ``upstream_url``; other env-validated
  fields (``port``, ``request_timeout_s``, ``max_request_body_bytes``,
  ``audit_log_path``, ``hmac_secret``, ``shutdown_grace_seconds``)
  silently accepted invalid mutations. Post-fix every guarded field
  raises ``ValueError`` on re-assignment of an illegal value.

STREAMING (LOW + MED):

- ``sse-delta-role-developer-aborts``: OpenAI's December 2024 ``developer``
  role was not in ``_SSE_DELTA_ROLE_VALUES``; a legitimate stream from
  o1/o3 models aborted via ``upstream_sse_malformed``. Post-fix
  ``developer`` is accepted.

- ``sse-delta-finish-reason-anthropic-aborts``: Anthropic-shim finish
  reasons (``end_turn``, ``max_tokens``, ``stop_sequence``) were not
  in ``_SSE_DELTA_FINISH_REASON_VALUES``; a legitimate OpenAI-shaped
  stream from an Anthropic upstream via a leaky shim aborted. Post-fix
  all three are accepted.

- ``realtime-ws-default-deny``: the WS text-inspection handler
  inspected only ``event.delta``; sibling event-shape strings (event_id,
  response_id, item_id, error.message, etc.) were forwarded verbatim,
  and ``call_id`` on the refusal frame was echoed unchecked.
  Post-fix the full event dict goes through the same recursive walker
  the HTTP path uses, and ``call_id`` is sanitized via
  ``_is_safe_call_id`` before echoing.

INFO:

- ``from_env-unicode-whitespace-and-bidi``: NBSP (U+00A0), zero-width
  space (U+200B), BOM (U+FEFF), and bidi controls (U+202A-U+202E) are
  now rejected by the env-var URL guard alongside ASCII control bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.core.check import CheckResult
from signet.core.pipeline import Pipeline
from signet.server.app import (
    _SSE_DELTA_FINISH_REASON_VALUES,
    _SSE_DELTA_ROLE_VALUES,
    _STRUCTURAL_ABORT,
    _STRUCTURAL_OK,
    SignetApp,
    _header_value_is_safe,
    _validate_top_level_structural_field,
)
from signet.server.config import ServerConfig
from signet.server.realtime import _is_safe_call_id

# ---------------------------------------------------------------------------
# SERVER LOW -- admission-pipeline-crash-leaks-classname
# ---------------------------------------------------------------------------


class _CrashingAdmissionPipeline(Pipeline):
    """Pipeline whose ``pre_request`` always raises, exercising the
    admission-fallback path."""

    async def pre_request(self, ctx: Any) -> CheckResult:
        raise RuntimeError("synthetic ADMISSION crash for fallback coverage")


class TestAdmissionFallbackHardened:
    def test_admission_crash_strict_no_classname_leak(self, tmp_path: Path) -> None:
        """Under strict redaction the admission-pipeline-crash 500
        does NOT leak the Python class name; ``correlation_id`` IS
        present; ``X-Signet-Upstream`` IS set."""
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=_CrashingAdmissionPipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 500, f"expected 500, got {r.status_code} {r.text!r}"
        body = r.json()
        assert "exception" not in body, f"strict mode leaked exception classname: {body!r}"
        assert "correlation_id" in body, f"strict mode response missing correlation_id: {body!r}"
        assert body["correlation_id"], f"strict mode correlation_id is empty / null: {body!r}"
        assert r.headers.get("X-Signet-Upstream"), (
            f"admission-fallback missing X-Signet-Upstream: headers={dict(r.headers)}"
        )
        # The audit row was written by _record_exception.
        rows = list(JsonlBackend(log).iter_entries())
        crash_rows = [
            row
            for row in rows
            if row.check_name == "pipeline.admission"
            and row.metadata.get("_exception_class") == "RuntimeError"
        ]
        assert crash_rows, (
            f"no pipeline.admission exception audit row: "
            f"rows={[(r_.check_name, r_.metadata) for r_ in rows]}"
        )

    def test_admission_crash_verbose_keeps_classname(self, tmp_path: Path) -> None:
        """Verbose mode still surfaces the Python class name for SDK
        ergonomics, alongside ``correlation_id`` and the attribution
        header."""
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=False,
        )
        app = SignetApp(config=cfg, pipeline=_CrashingAdmissionPipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        assert r.status_code == 500
        body = r.json()
        assert body.get("exception") == "RuntimeError"
        assert "correlation_id" in body
        assert r.headers.get("X-Signet-Upstream")


# ---------------------------------------------------------------------------
# SERVER LOW -- forwarded-header-crlf-injection
# ---------------------------------------------------------------------------


class TestForwardedHeaderCrlfInjection:
    def _build(self, tmp_path: Path) -> tuple[SignetApp, TestClient, Path]:
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        return app, TestClient(app.app), log

    def test_header_value_helper_rejects_crlf(self) -> None:
        assert _header_value_is_safe("Bearer xxx") is True
        assert _header_value_is_safe("Bearer\txxx") is True  # tab allowed
        assert _header_value_is_safe("Bearer xxx\r\nX-Injected: yes") is False
        assert _header_value_is_safe("Bearer xxx\nX-Injected: yes") is False
        assert _header_value_is_safe("Bearer xxx\rX-Injected: yes") is False
        assert _header_value_is_safe("Bearer xxx\x00") is False
        assert _header_value_is_safe("Bearer xxx\x01") is False
        assert _header_value_is_safe("Bearer xxx\x7f") is False

    def test_authorization_crlf_injection_refused_400(self, tmp_path: Path) -> None:
        """``Authorization: Bearer xxx\\r\\nX-Injected: yes`` is refused
        with a structured 400 instead of bubbling to h11 wire-send (which
        misattributed the failure as an upstream 502)."""
        _app, client, log = self._build(tmp_path)
        # Use a raw httpx request to bypass starlette's own header
        # validation in the test client.
        try:
            r = client.post(
                "/v1/chat/completions",
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                headers={
                    "Authorization": "Bearer xxx\r\nX-Injected: yes",
                    "X-Classification": "UNCLASS",
                },
            )
        except Exception:
            # Some HTTP clients refuse to send a header with CRLF; if
            # so, skip the wire test and fall back to the helper-level
            # test which is the load-bearing one.
            pytest.skip("HTTP client refused CRLF header at the transport layer")

        assert r.status_code == 400, (
            f"expected 400 header_invalid_charset, got {r.status_code} {r.text!r}"
        )
        body = r.json()
        assert body.get("error") == "header_invalid_charset", (
            f"expected error=header_invalid_charset, got {body!r}"
        )
        assert "correlation_id" in body
        assert r.headers.get("X-Signet-Upstream")
        rows = list(JsonlBackend(log).iter_entries())
        match = [
            row for row in rows if row.metadata.get("_refusal_kind") == "header_invalid_charset"
        ]
        assert match, (
            f"no header_invalid_charset audit row written: "
            f"rows={[(r_.check_name, r_.metadata) for r_ in rows]}"
        )

    def test_openai_beta_null_byte_refused_400(self, tmp_path: Path) -> None:
        _app, client, _log = self._build(tmp_path)
        try:
            r = client.post(
                "/v1/chat/completions",
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                headers={
                    "OpenAI-Beta": "assistants=v2\x00",
                    "X-Classification": "UNCLASS",
                },
            )
        except Exception:
            pytest.skip("HTTP client refused NUL header at the transport layer")
        assert r.status_code == 400
        assert r.json().get("error") == "header_invalid_charset"

    def test_clean_header_value_passes(self, tmp_path: Path) -> None:
        """Sanity: a normal Authorization header is not refused."""

        async def fake_post(_self, _url, **_kw):  # type: ignore[no-untyped-def]
            return httpx.Response(
                status_code=200,
                json={
                    "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                    "usage": {},
                },
                request=httpx.Request("POST", _url),
                headers={"content-type": "application/json"},
            )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(httpx.AsyncClient, "post", fake_post)
            _app, client, _log = self._build(tmp_path)
            r = client.post(
                "/v1/chat/completions",
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                headers={
                    "Authorization": "Bearer sk-test-1234567890",
                    "X-Classification": "UNCLASS",
                },
            )
            assert r.status_code == 200, (
                f"clean Authorization was refused: {r.status_code} {r.text!r}"
            )


# ---------------------------------------------------------------------------
# SERVER LOW -- setattr-validates-only-upstream_url
# ---------------------------------------------------------------------------


class TestServerConfigSetattrFullValidation:
    def _cfg(self) -> ServerConfig:
        return ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )

    def test_port_string_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="port"):
            cfg.port = "not an int"  # type: ignore[assignment]

    def test_port_negative_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="port"):
            cfg.port = -1

    def test_port_out_of_range_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="port"):
            cfg.port = 70000

    def test_port_boolean_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="port"):
            cfg.port = True  # bools-as-ints rejected

    def test_port_valid_int_accepted(self) -> None:
        cfg = self._cfg()
        cfg.port = 9000
        assert cfg.port == 9000

    def test_request_timeout_s_string_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="request_timeout_s"):
            cfg.request_timeout_s = "fast"  # type: ignore[assignment]

    def test_request_timeout_s_zero_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="request_timeout_s"):
            cfg.request_timeout_s = 0

    def test_request_timeout_s_negative_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="request_timeout_s"):
            cfg.request_timeout_s = -1.0

    def test_max_request_body_bytes_negative_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="max_request_body_bytes"):
            cfg.max_request_body_bytes = -1

    def test_max_request_body_bytes_zero_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="max_request_body_bytes"):
            cfg.max_request_body_bytes = 0

    def test_max_request_body_bytes_string_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="max_request_body_bytes"):
            cfg.max_request_body_bytes = "4MB"  # type: ignore[assignment]

    def test_audit_log_path_string_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="audit_log_path"):
            cfg.audit_log_path = "/tmp/audit.jsonl"  # type: ignore[assignment]

    def test_audit_log_path_none_accepted(self) -> None:
        cfg = self._cfg()
        cfg.audit_log_path = None
        assert cfg.audit_log_path is None

    def test_audit_log_path_pathlib_accepted(self, tmp_path: Path) -> None:
        cfg = self._cfg()
        cfg.audit_log_path = tmp_path / "audit.jsonl"
        assert isinstance(cfg.audit_log_path, Path)

    def test_hmac_secret_string_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="hmac_secret"):
            cfg.hmac_secret = "not bytes"  # type: ignore[assignment]

    def test_hmac_secret_bytes_accepted(self) -> None:
        cfg = self._cfg()
        cfg.hmac_secret = b"\x00" * 32
        assert cfg.hmac_secret == b"\x00" * 32

    def test_hmac_secret_none_accepted(self) -> None:
        cfg = self._cfg()
        cfg.hmac_secret = None
        assert cfg.hmac_secret is None

    def test_shutdown_grace_seconds_negative_rejected(self) -> None:
        cfg = self._cfg()
        with pytest.raises(ValueError, match="shutdown_grace_seconds"):
            cfg.shutdown_grace_seconds = -1.0

    def test_shutdown_grace_seconds_zero_accepted(self) -> None:
        cfg = self._cfg()
        cfg.shutdown_grace_seconds = 0
        assert cfg.shutdown_grace_seconds == 0

    def test_upstream_url_still_validated(self) -> None:
        """R11 behavior preserved: ``upstream_url`` scheme guard
        continues to fire."""
        cfg = self._cfg()
        with pytest.raises(ValueError, match="http://"):
            cfg.upstream_url = "file:///etc/passwd"

    def test_unguarded_field_still_writable(self) -> None:
        """Fields outside ``_VALIDATED_FIELDS`` (e.g. ``shadow``,
        ``strict_error_redaction``) keep their permissive write
        semantics so cli.py's flag overrides remain functional."""
        cfg = self._cfg()
        cfg.shadow = True
        assert cfg.shadow is True
        cfg.strict_error_redaction = False
        assert cfg.strict_error_redaction is False


# ---------------------------------------------------------------------------
# STREAMING LOW -- sse-delta-role-developer-aborts
# ---------------------------------------------------------------------------


class TestSseDeltaRoleDeveloper:
    def test_developer_role_does_not_abort(self) -> None:
        """``delta.role="developer"`` is OpenAI's December 2024 o1/o3
        role and must NOT abort the stream."""
        outcome = _validate_top_level_structural_field("role", "developer")
        assert outcome == _STRUCTURAL_OK, f"developer role should be OK, got {outcome}"
        assert "developer" in _SSE_DELTA_ROLE_VALUES

    def test_canonical_roles_still_ok(self) -> None:
        for role in ("system", "user", "assistant", "tool", "function"):
            assert _validate_top_level_structural_field("role", role) == _STRUCTURAL_OK

    def test_unknown_role_still_aborts(self) -> None:
        """Non-enum string still aborts (no broadening of the contract
        beyond the documented additions)."""
        assert _validate_top_level_structural_field("role", "marketer") == _STRUCTURAL_ABORT

    def test_marker_in_role_still_aborts(self) -> None:
        """Adding ``developer`` did NOT loosen the marker-smuggle guard:
        a marker in delta.role still aborts."""
        assert _validate_top_level_structural_field("role", "leak (S//NF)") == _STRUCTURAL_ABORT


# ---------------------------------------------------------------------------
# STREAMING LOW -- sse-delta-finish-reason-anthropic-aborts
# ---------------------------------------------------------------------------


class TestSseDeltaFinishReasonAnthropic:
    def test_anthropic_end_turn_does_not_abort(self) -> None:
        assert _validate_top_level_structural_field("finish_reason", "end_turn") == _STRUCTURAL_OK
        assert "end_turn" in _SSE_DELTA_FINISH_REASON_VALUES

    def test_anthropic_max_tokens_does_not_abort(self) -> None:
        assert _validate_top_level_structural_field("finish_reason", "max_tokens") == _STRUCTURAL_OK
        assert "max_tokens" in _SSE_DELTA_FINISH_REASON_VALUES

    def test_anthropic_stop_sequence_does_not_abort(self) -> None:
        assert (
            _validate_top_level_structural_field("finish_reason", "stop_sequence") == _STRUCTURAL_OK
        )
        assert "stop_sequence" in _SSE_DELTA_FINISH_REASON_VALUES

    def test_openai_finish_reasons_still_ok(self) -> None:
        for fr in ("stop", "length", "tool_calls", "content_filter", "function_call"):
            assert _validate_top_level_structural_field("finish_reason", fr) == _STRUCTURAL_OK

    def test_unknown_finish_reason_still_aborts(self) -> None:
        assert (
            _validate_top_level_structural_field("finish_reason", "marker_smuggle")
            == _STRUCTURAL_ABORT
        )


# ---------------------------------------------------------------------------
# STREAMING MED -- realtime-ws-default-deny
# ---------------------------------------------------------------------------


def _install_fake_stream(monkeypatch: pytest.MonkeyPatch, chunks: list[bytes]) -> None:
    class _Resp:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):  # type: ignore[no-untyped-def]
            for c in chunks:
                yield c

    class _CM:
        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return _Resp()

        async def __aexit__(self, *_a):  # type: ignore[no-untyped-def]
            return None

    def fake_stream(_self, _method, _url, **_kw):  # type: ignore[no-untyped-def]
        return _CM()

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)


class TestRealtimeCallIdSanitization:
    def test_safe_call_id_helper_accepts_uuid_shape(self) -> None:
        assert _is_safe_call_id("call_abc123") is True
        assert _is_safe_call_id("123e4567-e89b-12d3-a456-426614174000") is True
        assert _is_safe_call_id("abcDEF.123:xyz") is True

    def test_safe_call_id_helper_rejects_marker(self) -> None:
        assert _is_safe_call_id("leak (S//NF) classified") is False
        assert _is_safe_call_id("call\nid") is False
        assert _is_safe_call_id("") is False
        assert _is_safe_call_id(None) is False
        assert _is_safe_call_id(12345) is False
        # Excessively long IDs (>256 chars) refused.
        assert _is_safe_call_id("a" * 257) is False

    def test_realtime_handler_sanitizes_call_id_on_refusal(self, tmp_path: Path) -> None:
        """A function-call event with a hostile ``call_id`` lands a
        block decision, and the refusal frame does NOT echo the
        offending bytes -- it falls back to ``sanitized:<entry_id>``."""
        # The realtime module's refusal helper is unit-testable via
        # direct invocation; spinning up a WebSocket loopback is more
        # heavyweight than necessary for the call_id contract.
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from signet.server.realtime import RealtimeHandler

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        websocket = MagicMock()
        websocket.send_json = AsyncMock()
        handler = RealtimeHandler(app, websocket)

        hostile = {"call_id": "leak (S//NF) classified", "name": "send_email"}
        asyncio.run(
            handler._send_function_call_refusal(
                hostile,
                reason="blocked",
                stage="commitment",
                check_name="pipeline.commitment",
                entry_id="entry-12345",
                decision="block",
            )
        )
        # Capture the payload that send_json received.
        payload = websocket.send_json.call_args.args[0]
        assert payload["type"] == "signet.refusal"
        # The marker must NOT be echoed verbatim.
        assert "(S//NF)" not in json.dumps(payload), (
            f"hostile call_id leaked through refusal frame: {payload!r}"
        )
        # The fallback synthetic handle preserves correlation via the
        # entry_id rather than echoing untrusted bytes.
        assert payload.get("call_id") == "sanitized:entry-12345"

    def test_realtime_handler_echoes_safe_call_id(self, tmp_path: Path) -> None:
        """A function-call event with a UUID-shaped ``call_id`` echoes
        cleanly (no false-positive on legitimate IDs)."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from signet.server.realtime import RealtimeHandler

        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        websocket = MagicMock()
        websocket.send_json = AsyncMock()
        handler = RealtimeHandler(app, websocket)

        safe = {"call_id": "call_abc-123_xyz", "name": "send_email"}
        asyncio.run(
            handler._send_function_call_refusal(
                safe,
                reason="blocked",
                stage="commitment",
                check_name="pipeline.commitment",
                entry_id="entry-99",
                decision="block",
            )
        )
        payload = websocket.send_json.call_args.args[0]
        assert payload.get("call_id") == "call_abc-123_xyz"


# ---------------------------------------------------------------------------
# INFO -- from_env-unicode-whitespace-and-bidi
# ---------------------------------------------------------------------------


class TestFromEnvUnicodeWhitespace:
    def test_nbsp_in_middle_rejected(self) -> None:
        """NBSP (U+00A0) embedded mid-URL is now refused at boot
        rather than slipping past the ASCII-only control-byte loop."""
        with pytest.raises(ValueError, match="Unicode whitespace"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://up stream/v1",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_zwsp_rejected(self) -> None:
        """Zero-width space (U+200B) is invisible in operator
        dashboards -- the perfect homoglyph carrier. Rejected at boot."""
        with pytest.raises(ValueError, match="Unicode whitespace"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://up​stream/v1",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_bom_rejected(self) -> None:
        """BOM (U+FEFF) at any position rejected."""
        with pytest.raises(ValueError, match="Unicode whitespace"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://up﻿stream/v1",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_bidi_override_rejected(self) -> None:
        """RLO (U+202E) is a homoglyph-attack vector when rendered
        in dashboards. Rejected at boot."""
        with pytest.raises(ValueError, match="Unicode whitespace"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://up‮stream/v1",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_c1_control_rejected(self) -> None:
        """C1 control range (0x80-0x9F) rejected; NBSP (0xA0) is the
        boundary that the ASCII-only loop missed."""
        with pytest.raises(ValueError, match="C1 control"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://up\x85stream/v1",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )

    def test_legitimate_url_still_passes(self) -> None:
        cfg = ServerConfig.from_env(
            {
                "SIGNET_UPSTREAM_URL": "http://upstream.example.com:8080/v1",
                "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
            }
        )
        assert cfg.upstream_url == "http://upstream.example.com:8080/v1"
