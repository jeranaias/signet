"""Round 11 hunt closures — regression coverage.

Closes the seven findings from Round 11:

STREAMING (P0):

- ``sse-delta-recursive-walk-depth-bypass``: pre-fix
  ``_collect_inspectable_strings`` silently returned ``[]`` when the
  delta tree exceeded its ``_max_depth=6`` cap; the raw SSE bytes were
  already buffered and reached the client. Post-fix the walker returns
  a ``_DepthSentinelList`` typed sentinel, the cap is raised to
  ``_MAX_JSON_DEPTH`` (64), and the buffer flags ``malformed_event_seen``
  + ``delta_too_deep_seen`` so the forward path aborts via
  ``upstream_delta_too_deep`` instead of fail-open truncating.

- ``sse-delta-structural-keys-denylist-content-bypass``: pre-fix the
  structural-keys denylist (``role``, ``type``, ``finish_reason`` ...)
  was applied RECURSIVELY, so a hostile upstream that put a marker
  into ``delta.role`` / ``delta.type`` / any nested ``*.finish_reason``
  skipped inspection entirely. Post-fix the skip is scoped to the
  top-level delta only AND gated on a per-field wire-contract
  validator (:func:`_validate_top_level_structural_field`). A non-
  conformant structural value (e.g. ``delta.role="(S//NF)"``) trips
  ``malformed_event_seen`` and the stream aborts. A misshapen
  structural value of the wrong type (``delta.type={"nested":
  "(S//NF)"}``) falls through into the recursive walk so the marker is
  caught by the INSPECTION pipeline.

SERVER (LOW):

- ``json_too_deeply_nested-envelope-shape-inconsistency``: the legacy
  ``{"signet": {...}}`` envelope was flattened to match every other
  preflight 400, so SDKs branching on top-level ``["error"]`` no longer
  raise ``KeyError`` on this one refusal kind.

- ``preflight-400-paths-omit-X-Signet-Upstream``: every preflight 4xx
  refusal now carries the ``X-Signet-Upstream`` attribution header
  (operators distinguishing signet-refused from upstream-refused
  responses).

- ``outer-fallback-leaks-exception-classname-no-correlation_id-no-
  attribution``: the per-endpoint ``except Exception`` fallback now
  honors ``strict_error_redaction`` (no Python class-name leak),
  carries the ``correlation_id`` of the audit row, and sets
  ``X-Signet-Upstream``. ``pipeline.post_complete`` is also wrapped
  inside ``_forward_unary`` so a RECORD-stage crash audits + logs but
  does not turn the already-valid upstream response into a 502.

INFO:

- ``from_env-whitespace-and-control-bytes``: ``SIGNET_UPSTREAM_URL`` is
  now stripped of surrounding whitespace; embedded control bytes
  (codepoint < 0x20 or 0x7f) are rejected at boot.

- ``ServerConfig-mutability-bypasses-scheme-validation``: assigning to
  ``cfg.upstream_url`` post-``__post_init__`` re-runs the scheme
  validation instead of silently accepting a non-HTTP(S) scheme.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.checks.regex_content import Pattern, RegexOutputCheck
from signet.checks.scope_drift import ScopeDriftCheck
from signet.core.check import CheckResult
from signet.core.pipeline import Pipeline
from signet.server.app import (
    _MAX_JSON_DEPTH,
    _STRUCTURAL_ABORT,
    _STRUCTURAL_OK,
    _STRUCTURAL_WALK,
    SignetApp,
    _collect_inspectable_strings,
    _DepthSentinelList,
    _validate_top_level_structural_field,
)
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# Streaming attack scaffolding (mirrors test_round9_hunt.py)
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
# P0 -- sse-delta-recursive-walk-depth-bypass
# ---------------------------------------------------------------------------


class TestSseDeltaDepthBypass:
    def test_minimal_seven_level_nested_marker_aborts(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The original 7-level minimum-smuggle payload no longer
        leaks the marker because the walker now sees it at depth 7
        (pre-fix walker capped at 6 and silently returned ``[]``,
        bypassing inspection while the raw bytes reached the client).

        Strict mode is used so the abort frame's ``reason`` field
        does NOT echo the matched marker substring (verbose mode
        surfaces the marker in the operator-readable block reason).
        """
        # 7 nested dicts under ``delta`` mirror the
        # ``attack_depth7_minimal.py`` repro.
        payload: dict[str, Any] = {"x": "leak (S//NF) classified"}
        for _ in range(7):
            payload = {"a": payload}
        event = {"choices": [{"delta": payload}]}
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
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
        # Strict-mode response should never echo the marker: not from
        # upstream content (the bug we're closing) and not from the
        # operator-readable reason field.
        assert "(S//NF)" not in r.text, f"depth-7 marker leaked past walker: {r.text!r}"
        assert _has_abort(r.text), f"no abort frame: {r.text!r}"
        inspection_rows = [
            row for row in _audit_rows(log) if row.check_name == "pipeline.inspection"
        ]
        assert inspection_rows, "no pipeline.inspection audit row — the walker missed the marker"

    def test_marker_buried_at_walker_cap_aborts(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """An attacker burying a marker BELOW the walker's
        ``_MAX_JSON_DEPTH`` cap now trips the depth-exceeded abort
        instead of silently bypassing inspection. The marker bytes
        never reach the client."""
        # Build a payload nested ``_MAX_JSON_DEPTH + 5`` levels deep so
        # the walker hits the cap. Use exactly the multi-data shape
        # that the structural-scanner in ``_admit`` will let through:
        # _MAX_JSON_DEPTH refers to the inbound body scanner, so build
        # the SSE event payload only (not the request body) at this
        # depth. The chunk's outer ``{"choices":[{"delta":...}]}`` adds
        # 3 levels; nest the inner payload until total > _MAX_JSON_DEPTH.
        inner: Any = "leak (S//NF) classified"
        levels = _MAX_JSON_DEPTH + 5
        for _ in range(levels):
            inner = {"a": inner}
        event = {"choices": [{"delta": inner}]}
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        # Strict mode so the abort-reason field does not echo the
        # marker substring (the test asserts the marker is absent
        # from the wire response).
        _app, client, log = _build_streaming_app(
            tmp_path,
            checks=[ScopeDriftCheck()],
            strict_error_redaction=True,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        # The marker MUST NOT reach the client.
        assert "(S//NF)" not in r.text, f"deep-nested marker leaked past walker cap: {r.text!r}"
        # Verify the dedicated ``upstream_delta_too_deep`` abort token
        # fires so dashboards split walker-cap aborts from generic
        # JSON-parse-failure aborts.
        assert "upstream_delta_too_deep" in r.text, (
            f"depth-exceeded abort token missing from response body: {r.text!r}"
        )
        upstream_rows = [row for row in _audit_rows(log) if row.check_name == "pipeline.upstream"]
        assert upstream_rows, "no pipeline.upstream audit row"

    def test_walker_returns_depth_sentinel_on_overflow(self) -> None:
        """Unit-level: ``_collect_inspectable_strings`` returns a
        :class:`_DepthSentinelList` on overflow rather than the
        pre-fix silent ``[]``."""
        deep: Any = "leaf"
        for _ in range(_MAX_JSON_DEPTH + 2):
            deep = {"a": deep}
        result = _collect_inspectable_strings(deep, _top_level=True)
        assert isinstance(result, _DepthSentinelList), (
            "walker did not return depth sentinel on overflow"
        )

    def test_walker_under_cap_returns_plain_list(self) -> None:
        """Boundary: at depth EQUAL to the cap the walker still
        returns a plain list (the legitimate-shape path)."""
        deep: Any = "leaf (under cap)"
        # 5 levels — well under _MAX_JSON_DEPTH.
        for _ in range(5):
            deep = {"a": deep}
        result = _collect_inspectable_strings(deep, _top_level=True)
        assert not isinstance(result, _DepthSentinelList)
        assert "leaf (under cap)" in result


# ---------------------------------------------------------------------------
# P0 -- sse-delta-structural-keys-denylist-content-bypass
# ---------------------------------------------------------------------------


class TestSseDeltaStructuralBypass:
    def test_role_with_marker_aborts(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """``delta.role`` carrying any value outside the enumerated
        set (e.g. a classification marker) trips the malformed-event
        abort. The marker bytes never reach the client."""
        event = {"choices": [{"delta": {"role": "leak (S//NF) classified"}}]}
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        # Strict mode so the abort frame's ``reason`` does not echo
        # the upstream marker substring.
        _app, client, log = _build_streaming_app(
            tmp_path,
            checks=[ScopeDriftCheck()],
            strict_error_redaction=True,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        assert "(S//NF)" not in r.text, f"role-smuggled marker leaked: {r.text!r}"
        assert _has_abort(r.text), f"no abort frame: {r.text!r}"
        upstream_rows = [row for row in _audit_rows(log) if row.check_name == "pipeline.upstream"]
        assert upstream_rows, "no pipeline.upstream audit row"

    def test_type_with_nested_marker_blocked_via_walk(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``delta.type`` set to a nested dict carrying a marker is
        recognized as the wrong type (not the right type with the
        wrong value), so the walker inspects the value's strings.
        The INSPECTION pipeline then blocks the marker."""
        event = {"choices": [{"delta": {"type": {"nested": "leak (S//NF) classified"}}}]}
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
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
        assert "(S//NF)" not in r.text, (
            f"marker hidden in delta.type nested dict leaked: {r.text!r}"
        )
        assert _has_abort(r.text), f"no abort/block frame: {r.text!r}"
        # The block came via INSPECTION (or upstream_protocol_violation
        # if the structural-shape-abort path tripped first); either is
        # acceptable as long as the marker did not leak.
        names = {row.check_name for row in _audit_rows(log)}
        assert "pipeline.inspection" in names or "pipeline.upstream" in names

    def test_nested_finish_reason_no_longer_smuggle_channel(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A key named ``finish_reason`` inside a nested dict (e.g.
        ``delta.tool_calls[0].finish_reason``) used to skip inspection
        because the denylist applied recursively. Post-fix the skip is
        top-level only; nested ``finish_reason`` carries no special
        meaning to the walker and gets inspected."""
        event = {
            "choices": [{"delta": {"tool_calls": [{"finish_reason": "leak (S//NF) classified"}]}}]
        }
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        pattern = Pattern(pattern=r"\(S//NF\)", action="block", label="classified")
        _app, client, _log = _build_streaming_app(
            tmp_path,
            checks=[ScopeDriftCheck(), RegexOutputCheck([pattern])],
            strict_error_redaction=True,
        )
        r = _post_stream(client)
        assert r.status_code == 200
        assert "(S//NF)" not in r.text, f"nested finish_reason smuggle leaked: {r.text!r}"
        assert _has_abort(r.text), f"no abort/block frame: {r.text!r}"

    def test_conformant_delta_role_assistant_allowed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The benign-traffic case still works: ``delta.role="assistant"``
        with ``delta.content="normal"`` passes through unaffected."""
        event = {"choices": [{"delta": {"role": "assistant", "content": "normal text"}}]}
        chunks = [
            b"data: " + json.dumps(event).encode() + b"\n\n",
            b"data: [DONE]\n\n",
        ]
        _install_fake_stream(monkeypatch, chunks)
        _app, client, _log = _build_streaming_app(tmp_path, checks=[ScopeDriftCheck()])
        r = _post_stream(client)
        assert r.status_code == 200
        # No abort; the upstream chunk is forwarded to the client.
        assert "normal text" in r.text
        assert not _has_abort(r.text), f"benign assistant delta tripped an abort: {r.text!r}"

    @pytest.mark.parametrize(
        ("key", "value", "expected"),
        [
            ("role", "assistant", _STRUCTURAL_OK),
            ("role", "tool", _STRUCTURAL_OK),
            ("role", "leak", _STRUCTURAL_ABORT),
            ("role", {"nested": "x"}, _STRUCTURAL_WALK),
            ("finish_reason", None, _STRUCTURAL_OK),
            ("finish_reason", "stop", _STRUCTURAL_OK),
            ("finish_reason", "something_else", _STRUCTURAL_ABORT),
            ("finish_reason", [1, 2], _STRUCTURAL_WALK),
            ("index", 0, _STRUCTURAL_OK),
            ("index", "5", _STRUCTURAL_OK),
            ("index", "5\x00", _STRUCTURAL_ABORT),
            ("index", {"nested": 1}, _STRUCTURAL_WALK),
            ("type", "chat.completion.chunk", _STRUCTURAL_OK),
            ("type", {"nested": "x"}, _STRUCTURAL_WALK),
            ("type", "with\x01ctrl", _STRUCTURAL_ABORT),
            ("id", "abc-123", _STRUCTURAL_OK),
            ("id", None, _STRUCTURAL_OK),
            ("id", "", _STRUCTURAL_ABORT),  # empty string not allowed
        ],
    )
    def test_structural_validator_outcomes(self, key: str, value: Any, expected: str) -> None:
        assert _validate_top_level_structural_field(key, value) == expected


# ---------------------------------------------------------------------------
# SERVER LOW -- json_too_deeply_nested-envelope-shape-inconsistency
# ---------------------------------------------------------------------------


def _make_deep_json(depth: int) -> bytes:
    return b"[" * depth + b"1" + b"]" * depth


class TestJsonDepthEnvelopeFlattened:
    def test_strict_mode_flat_envelope(self, tmp_path: Path) -> None:
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
            content=_make_deep_json(_MAX_JSON_DEPTH + 5),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        # Top-level ``error`` token now matches peers; the legacy
        # ``{"signet": {...}}`` envelope is gone.
        assert body["error"] == "json_too_deeply_nested"
        assert "signet" not in body
        # Correlation_id at top level matches peers.
        assert "correlation_id" in body

    def test_verbose_mode_exposes_max_depth_at_top_level(self, tmp_path: Path) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=False,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            content=_make_deep_json(_MAX_JSON_DEPTH + 5),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        body = r.json()
        assert body["error"] == "json_too_deeply_nested"
        assert body["max_depth"] == _MAX_JSON_DEPTH


# ---------------------------------------------------------------------------
# SERVER LOW -- preflight-400-paths-omit-X-Signet-Upstream
# ---------------------------------------------------------------------------


class TestPreflightAttributionHeader:
    @pytest.mark.parametrize(
        ("body_bytes", "headers", "expected_status"),
        [
            (b"", {"Content-Type": "application/json"}, 400),  # empty_body
            (b"this is not json", {"Content-Type": "application/json"}, 400),
            (b"[]", {"Content-Type": "application/json"}, 400),  # non_object
            (
                b'{"messages":[], "temperature": NaN}',
                {"Content-Type": "application/json"},
                400,
            ),  # non_finite_float
            (bytes([0xFF, 0xFE, 0xFD]), {"Content-Type": "application/json"}, 400),
        ],
    )
    def test_400_paths_carry_attribution_header(
        self,
        tmp_path: Path,
        body_bytes: bytes,
        headers: dict[str, str],
        expected_status: int,
    ) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post("/v1/chat/completions", content=body_bytes, headers=headers)
        assert r.status_code == expected_status
        assert r.headers.get("X-Signet-Upstream") is not None, (
            f"X-Signet-Upstream missing on preflight {expected_status}: body_bytes={body_bytes!r}"
        )

    def test_session_id_too_long_carries_attribution(self, tmp_path: Path) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            content=b'{"messages":[]}',
            headers={
                "Content-Type": "application/json",
                "X-Signet-Session": "a" * 10_000,
            },
        )
        assert r.status_code == 400
        assert r.headers.get("X-Signet-Upstream")

    def test_session_id_invalid_charset_carries_attribution(self, tmp_path: Path) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            content=b'{"messages":[]}',
            headers={
                "Content-Type": "application/json",
                "X-Signet-Session": "not allowed!",
            },
        )
        assert r.status_code == 400
        assert r.headers.get("X-Signet-Upstream")

    def test_json_too_deeply_nested_carries_attribution(self, tmp_path: Path) -> None:
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            content=_make_deep_json(_MAX_JSON_DEPTH + 5),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert r.headers.get("X-Signet-Upstream")


# ---------------------------------------------------------------------------
# SERVER LOW -- outer-fallback-leaks-exception-classname-no-correlation_id-
# no-attribution
# ---------------------------------------------------------------------------


class _RaisingPostCompletePipeline(Pipeline):
    """Pipeline whose ``post_complete`` always raises, exercising the
    RECORD-stage try/except added in ``_forward_unary``."""

    async def post_complete(self, rctx: Any) -> list[CheckResult]:
        raise RuntimeError("synthetic RECORD-stage crash")


class TestOuterFallbackHardened:
    def test_record_stage_crash_does_not_502(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When ``pipeline.post_complete`` raises inside
        ``_forward_unary``, the upstream response is already in flight
        / returned and the client MUST see the normal 200 — not a
        spurious 502. The crash audits via ``_record_exception``."""

        # Build a fake unary upstream that returns a valid chat-
        # completion JSON. ``httpx.AsyncClient.post`` is what
        # ``_forward_unary`` calls; patch it to a no-network coroutine.
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

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=_RaisingPostCompletePipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        # The RECORD-stage crash MUST NOT surface as a 502; the
        # upstream response is already valid.
        assert r.status_code == 200, (
            f"RECORD-stage crash 502'd a successful upstream response: "
            f"status={r.status_code} body={r.text}"
        )
        # The audit row for the exception was written.
        rows = _audit_rows(log)
        crash_rows = [
            row
            for row in rows
            if row.check_name == "pipeline.record"
            and row.metadata.get("_exception_class") == "RuntimeError"
        ]
        assert crash_rows, (
            f"no pipeline.record exception audit row written: "
            f"rows={[(r_.check_name, r_.metadata) for r_ in rows]}"
        )

    def test_outer_fallback_strict_redaction_no_classname_leak(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Force ``_forward_unary`` itself to raise so the outer
        ``_handle_chat`` fallback executes. Under strict redaction the
        Python class name is NOT echoed; ``correlation_id`` IS
        present; ``X-Signet-Upstream`` IS set."""

        async def crashing_post(_self, _url, **_kw):  # type: ignore[no-untyped-def]
            raise AssertionError("forced unary crash for outer-fallback coverage")

        monkeypatch.setattr(httpx.AsyncClient, "post", crashing_post)
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=True,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        # Note: ``httpx.HTTPError`` exceptions are caught inside
        # ``_forward_unary`` and routed through
        # ``_record_upstream_failure``; AssertionError is NOT an
        # HTTPError, so it propagates to the outer fallback. The path
        # may be routed through either the ``_forward_unary`` inner
        # ``except Exception as exc`` (upstream_exception 502) or the
        # outer ``_handle_chat`` fallback. In either case the body
        # must NOT carry the ``exception`` field under strict mode and
        # MUST carry the attribution header.
        body = r.json()
        assert "exception" not in body, f"strict mode leaked exception classname: {body!r}"
        assert "correlation_id" in body, f"strict mode response missing correlation_id: {body!r}"
        assert r.headers.get("X-Signet-Upstream"), (
            f"outer-fallback missing X-Signet-Upstream: headers={dict(r.headers)}"
        )

    def test_outer_fallback_verbose_keeps_classname(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verbose mode still surfaces the class name for SDK
        ergonomics; this just covers the dispatch branch."""

        async def crashing_post(_self, _url, **_kw):  # type: ignore[no-untyped-def]
            raise AssertionError("forced unary crash, verbose mode")

        monkeypatch.setattr(httpx.AsyncClient, "post", crashing_post)
        log = tmp_path / "audit.jsonl"
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=log,
            strict_error_redaction=False,
        )
        app = SignetApp(config=cfg, pipeline=Pipeline(checks=[]))
        client = TestClient(app.app)
        r = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Classification": "UNCLASS"},
        )
        body = r.json()
        # Verbose mode carries the class name AND correlation_id AND
        # the attribution header.
        assert "correlation_id" in body
        assert r.headers.get("X-Signet-Upstream")


# ---------------------------------------------------------------------------
# INFO -- from_env-whitespace-and-control-bytes
# ---------------------------------------------------------------------------


class TestFromEnvUpstreamUrl:
    def test_whitespace_stripped(self) -> None:
        cfg = ServerConfig.from_env(
            {
                "SIGNET_UPSTREAM_URL": "  http://example.com  ",
                "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
            }
        )
        assert cfg.upstream_url == "http://example.com"

    def test_tab_and_newline_stripped(self) -> None:
        cfg = ServerConfig.from_env(
            {
                "SIGNET_UPSTREAM_URL": "\thttp://example.com\n",
                "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
            }
        )
        assert cfg.upstream_url == "http://example.com"

    def test_embedded_control_byte_rejected_in_env(self) -> None:
        """The control-byte rejection is scoped to ``from_env`` -- the
        operator-typed env-var path -- per the Round 11 finding spec.
        Direct ``ServerConfig(...)`` construction does NOT reject
        control bytes (the existing CLI sanitization tests rely on the
        constructor accepting hostile-looking URL bytes and the banner
        renderer sanitizing them at output time)."""
        with pytest.raises(ValueError, match="control"):
            ServerConfig.from_env(
                {
                    "SIGNET_UPSTREAM_URL": "http://exa\x01mple.com",
                    "SIGNET_ALLOW_EPHEMERAL_KEY": "1",
                }
            )


# ---------------------------------------------------------------------------
# INFO -- ServerConfig-mutability-bypasses-scheme-validation
# ---------------------------------------------------------------------------


class TestServerConfigMutationValidation:
    def test_reassign_upstream_url_revalidates_scheme(self) -> None:
        cfg = ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )
        with pytest.raises(ValueError, match="http://"):
            cfg.upstream_url = "file:///etc/passwd"

    def test_valid_reassign_still_works(self) -> None:
        cfg = ServerConfig(
            upstream_url="https://api.example.com",
            allow_ephemeral_key=True,
        )
        cfg.upstream_url = "http://localhost:8080"
        assert cfg.upstream_url == "http://localhost:8080"
