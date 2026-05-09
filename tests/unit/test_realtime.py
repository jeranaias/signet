"""Tests for the WebSocket realtime API pass-through (v0.1.6 A5).

The proxy auto-detects the realtime endpoint at ``/v1/realtime``. ADMISSION
runs once at connect time against the WebSocket handshake headers.
COMMITMENT runs on every function-call event in the session. RECORD writes
session-start, periodic flush, and session-end audit rows. INSPECTION runs
on text chunks; audio frames pass through unchanged with a metadata-only
audit row.

Coverage:

1. ``TestAdmission`` — connect with no commit-owner header; expect a
   1008 close. Audit row records the refusal.
2. ``TestCommitmentBlock`` — connect with a valid owner and an empty
   tool registry; emit a function-call event for an unregistered tool;
   expect a ``signet.refusal`` event back, NOT a forwarded function
   call.
3. ``TestCommitmentEscalate`` — register a HIGH-tier irreversible tool;
   expect an ``escalate`` decision in the refusal event with the
   approval-chain metadata surfaced.
4. ``TestCommitmentBlockShadow`` — same scenario as #2 but with
   ``config.shadow=True``. Expect the function-call event IS forwarded
   (shadow neutralizes the block); audit row tagged ``shadow=True``.
5. ``TestAudioPassthrough`` — send an audio event; confirm it forwards
   unchanged and an audit row with ``audio_inspection_skipped=True``
   exists.
6. ``TestSessionLifecycle`` — connect, send a few events, disconnect.
   Confirm session-start and session-end audit rows are present with
   the documented metadata fields.
7. ``TestPeriodicFlush`` — patches the flush-interval constant to a
   tiny value and confirms a flush row gets written. The 30-second
   default would be too slow for a unit test; integration test
   territory documents the live cadence.

Test harness: FastAPI's :meth:`fastapi.testclient.TestClient.websocket_connect`
drives the proxy without a real network. The in-tree
:class:`signet.server.realtime.RealtimeHandler` is loopback (echoes
unmatched events) so we can observe which events the dispatcher
forwarded and which it withheld behind a refusal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from signet.audit.backend import JsonlBackend
from signet.checks import OwnerResolutionCheck
from signet.checks.tool_call_inspector import (
    RiskTier,
    ToolCallInspectorCheck,
    ToolSpec,
)
from signet.core.pipeline import Pipeline
from signet.server import realtime as realtime_mod
from signet.server.app import SignetApp
from signet.server.config import ServerConfig

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _make_app(
    *,
    pipeline: Pipeline,
    audit_log_path: Path,
    shadow: bool = False,
    strict_error_redaction: bool = False,
) -> tuple[SignetApp, TestClient]:
    """Construct a SignetApp + TestClient pair for one test.

    Defaults match the most common assertions: an audit log so rows
    can be inspected, verbose errors so reason/check fields are
    present in the wire frames, no shadow.
    """
    config = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=audit_log_path,
        shadow=shadow,
        strict_error_redaction=strict_error_redaction,
    )
    app = SignetApp(config=config, pipeline=pipeline)
    return app, TestClient(app.app)


def _read_entries(audit_log_path: Path) -> list[Any]:
    """Read every audit row written so far. Empty list when the chain
    hasn't been opened yet (e.g. a test that closed before any row
    was written)."""
    if not audit_log_path.exists():
        return []
    return list(JsonlBackend(audit_log_path).iter_entries())


# ---------------------------------------------------------------------------
# 1. ADMISSION refuses at connect
# ---------------------------------------------------------------------------


class TestAdmission:
    """No commit-owner header → close 1008 + audit row."""

    def test_no_owner_header_closes_1008(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            audit_log_path=log,
        )
        from starlette.websockets import WebSocketDisconnect

        with (
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect("/v1/realtime") as ws,
        ):
            # The server emits a refusal event before close, so
            # the first receive should land us the JSON event;
            # the receive AFTER that raises a disconnect.
            event = ws.receive_json()
            assert event["type"] == "signet.refusal"
            assert event["stage"] == "admission"
            # Verbose mode in this fixture: reason + check are
            # present (strict mode is off by default in _make_app).
            assert event.get("correlation_id")
            # This receive raises with the close code attached.
            ws.receive_json()
        # The Starlette TestClient signals close via WebSocketDisconnect;
        # the code is on the exception.
        assert excinfo.value.code == realtime_mod.WS_CLOSE_POLICY_VIOLATION

        # Audit chain captures the admission refusal.
        entries = _read_entries(log)
        admission_rows = [e for e in entries if e.check_name == "pipeline.admission"]
        assert len(admission_rows) == 1
        assert admission_rows[0].decision.value == "block"
        # Session-start / session-end were NOT written because admission
        # closed the session before they fire.
        assert not any(
            e.check_name in {"pipeline.realtime.session_start",
                              "pipeline.realtime.session_end"}
            for e in entries
        )

    def test_admission_refusal_in_shadow_closes_1000(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        _, client = _make_app(
            pipeline=Pipeline(checks=[OwnerResolutionCheck(require_owner=True)]),
            audit_log_path=log,
            shadow=True,
        )
        from starlette.websockets import WebSocketDisconnect

        with (
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect("/v1/realtime") as ws,
        ):
            event = ws.receive_json()
            assert event["type"] == "signet.shadow"
            assert event["stage"] == "admission"
            assert event["decision"] == "block"
            assert event["would_have_closed_code"] == \
                realtime_mod.WS_CLOSE_POLICY_VIOLATION
            ws.receive_json()  # raises disconnect
        assert excinfo.value.code == realtime_mod.WS_CLOSE_NORMAL

        entries = _read_entries(log)
        admission_rows = [e for e in entries if e.check_name == "pipeline.admission"]
        assert len(admission_rows) == 1
        # Shadow tags the audit row.
        assert admission_rows[0].metadata.get("shadow") is True


# ---------------------------------------------------------------------------
# 2. COMMITMENT block (non-shadow)
# ---------------------------------------------------------------------------


def _commit_owner_headers() -> dict[str, str]:
    """Standard X-Commit-Owner header set so ADMISSION resolves."""
    return {"X-Commit-Owner": "human:alice@example.com"}


def _function_call_event(name: str, *, call_id: str = "call_1") -> dict[str, Any]:
    """Shape a realtime API ``response.function_call_arguments.done`` event."""
    return {
        "type": realtime_mod.EVENT_FUNCTION_CALL_DONE,
        "name": name,
        "call_id": call_id,
        "arguments": json.dumps({"target": "x"}),
    }


class TestCommitmentBlock:
    """Unregistered tool → refusal event back, function call NOT echoed."""

    def test_block_emits_refusal(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        # Empty registry + allow_unregistered=False → tool blocks.
        inspector = ToolCallInspectorCheck(
            registry={}, allow_unregistered=False
        )
        pipeline = Pipeline(
            checks=[OwnerResolutionCheck(require_owner=True), inspector]
        )
        _, client = _make_app(pipeline=pipeline, audit_log_path=log)

        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            ws.send_json(_function_call_event("send_email"))
            event = ws.receive_json()

        assert event["type"] == "signet.refusal"
        assert event["stage"] == "commitment"
        assert event["decision"] == "block"
        assert event["tool_name"] == "send_email"
        assert event["call_id"] == "call_1"
        assert event.get("correlation_id")
        assert event.get("check") == "tool_call_inspector"

        # Audit rows: session-start, commitment block, session-end.
        entries = _read_entries(log)
        names = [e.check_name for e in entries]
        assert "pipeline.realtime.session_start" in names
        assert "pipeline.realtime.session_end" in names
        commit_rows = [
            e for e in entries if e.check_name == "tool_call_inspector"
        ]
        assert len(commit_rows) == 1
        assert commit_rows[0].decision.value == "block"

        end_row = next(
            e for e in entries if e.check_name == "pipeline.realtime.session_end"
        )
        assert end_row.metadata["function_calls_count"] == 1
        assert end_row.metadata["function_calls_blocked"] == 1
        assert end_row.metadata["function_calls_escalated"] == 0


# ---------------------------------------------------------------------------
# 3. COMMITMENT escalate (HIGH-tier irreversible)
# ---------------------------------------------------------------------------


class TestCommitmentEscalate:
    """HIGH-tier irreversible tool → escalate decision + approval chain."""

    def test_escalate_emits_approval_chain(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        registry = {
            "transfer_funds": ToolSpec(
                risk_tier=RiskTier.HIGH, irreversible=True
            )
        }
        inspector = ToolCallInspectorCheck(
            registry=registry, escalate_at_tier=RiskTier.HIGH
        )
        pipeline = Pipeline(
            checks=[OwnerResolutionCheck(require_owner=True), inspector]
        )
        _, client = _make_app(pipeline=pipeline, audit_log_path=log)

        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            ws.send_json(_function_call_event("transfer_funds"))
            event = ws.receive_json()

        assert event["type"] == "signet.refusal"
        assert event["decision"] == "escalate"
        assert event["tool_name"] == "transfer_funds"
        # The approval chain metadata from A6 surfaces on the wire.
        approval = event.get("approval_chain")
        assert approval is not None
        assert approval.get("requires_approval_from")
        assert approval.get("current_approver") == "human:alice@example.com"

        end_row = next(
            e
            for e in _read_entries(log)
            if e.check_name == "pipeline.realtime.session_end"
        )
        assert end_row.metadata["function_calls_escalated"] == 1
        assert end_row.metadata["function_calls_blocked"] == 0


# ---------------------------------------------------------------------------
# 4. COMMITMENT block in shadow → forwarded
# ---------------------------------------------------------------------------


class TestCommitmentBlockShadow:
    """Shadow mode neutralizes the block — the function call IS forwarded."""

    def test_shadow_forwards_blocked_call(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        inspector = ToolCallInspectorCheck(
            registry={}, allow_unregistered=False
        )
        pipeline = Pipeline(
            checks=[OwnerResolutionCheck(require_owner=True), inspector]
        )
        _, client = _make_app(
            pipeline=pipeline, audit_log_path=log, shadow=True
        )

        original = _function_call_event("send_email")
        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            ws.send_json(original)
            echoed = ws.receive_json()

        # Loopback echoes the function-call event because shadow let
        # it through. (No refusal frame on the wire.)
        assert echoed["type"] == realtime_mod.EVENT_FUNCTION_CALL_DONE
        assert echoed["name"] == "send_email"

        # Audit row still records the would-have-been-block, tagged shadow.
        commit_rows = [
            e
            for e in _read_entries(log)
            if e.check_name == "tool_call_inspector"
        ]
        assert len(commit_rows) == 1
        assert commit_rows[0].decision.value == "block"
        assert commit_rows[0].metadata.get("shadow") is True


# ---------------------------------------------------------------------------
# 5. Audio pass-through with audit row
# ---------------------------------------------------------------------------


class TestAudioPassthrough:
    """Audio events forward unchanged + leave an audit row."""

    def test_audio_event_passes_through(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
        _, client = _make_app(pipeline=pipeline, audit_log_path=log)

        audio_event = {
            "type": realtime_mod.EVENT_AUDIO_INPUT,
            "audio": "base64-bytes-here",
        }
        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            ws.send_json(audio_event)
            echoed = ws.receive_json()

        assert echoed["type"] == realtime_mod.EVENT_AUDIO_INPUT
        assert echoed["audio"] == "base64-bytes-here"

        audio_rows = [
            e
            for e in _read_entries(log)
            if e.check_name == "pipeline.realtime.audio"
        ]
        assert len(audio_rows) == 1
        assert audio_rows[0].metadata["audio_inspection_skipped"] is True
        assert audio_rows[0].metadata["event_type"] == \
            realtime_mod.EVENT_AUDIO_INPUT

        # Session-end metrics reflect the audio frame.
        end_row = next(
            e
            for e in _read_entries(log)
            if e.check_name == "pipeline.realtime.session_end"
        )
        assert end_row.metadata["audio_chunks_passed_through"] == 1


# ---------------------------------------------------------------------------
# 6. Session-start / session-end audit rows
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Connect, drive a few events, confirm both bracket rows exist."""

    def test_session_start_and_end_rows(self, tmp_path) -> None:
        log = tmp_path / "audit.jsonl"
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
        _, client = _make_app(pipeline=pipeline, audit_log_path=log)

        # An unrecognized event type echoes via the loopback dispatcher;
        # this exercises the client-event-counter without firing any
        # stage logic.
        passthrough_event = {"type": "session.update", "session": {}}
        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            ws.send_json(passthrough_event)
            ws.receive_json()
            ws.send_json(passthrough_event)
            ws.receive_json()

        entries = _read_entries(log)
        starts = [
            e
            for e in entries
            if e.check_name == "pipeline.realtime.session_start"
        ]
        ends = [
            e for e in entries if e.check_name == "pipeline.realtime.session_end"
        ]
        assert len(starts) == 1
        assert len(ends) == 1

        # Session-start metadata.
        start_meta = starts[0].metadata
        assert "session_id" in start_meta
        assert "connected_at" in start_meta

        # Session-end metadata: every documented field is populated.
        end_meta = ends[0].metadata
        for key in (
            "session_id",
            "duration_seconds",
            "function_calls_count",
            "function_calls_blocked",
            "function_calls_escalated",
            "client_event_count",
            "upstream_event_count",
            "audio_chunks_passed_through",
            "text_chunks_inspected",
            "ended_normally",
            "close_code",
        ):
            assert key in end_meta, f"session-end row missing {key!r}"
        assert end_meta["session_id"] == start_meta["session_id"]
        assert end_meta["client_event_count"] == 2
        assert end_meta["function_calls_count"] == 0
        assert end_meta["audio_chunks_passed_through"] == 0


# ---------------------------------------------------------------------------
# 7. Periodic flush — patch the interval to keep the test fast
# ---------------------------------------------------------------------------


class TestPeriodicFlush:
    """Confirm the flush task writes a checkpoint row at the interval.

    The 30-second production cadence is too slow for unit tests; we
    monkeypatch :data:`signet.server.realtime.FLUSH_INTERVAL_SECONDS`
    to a tiny value and let the asyncio scheduler tick the flush task
    a couple of times before closing. Integration-test territory
    documents the live cadence.
    """

    def test_flush_row_written(self, monkeypatch, tmp_path) -> None:
        # 50 ms cadence — fast enough to write at least one flush
        # while we hold the connection open.
        monkeypatch.setattr(realtime_mod, "FLUSH_INTERVAL_SECONDS", 0.05)

        log = tmp_path / "audit.jsonl"
        pipeline = Pipeline(checks=[OwnerResolutionCheck(require_owner=True)])
        _, client = _make_app(pipeline=pipeline, audit_log_path=log)

        with client.websocket_connect(
            "/v1/realtime", headers=_commit_owner_headers()
        ) as ws:
            # Hold the connection open long enough for the flush task
            # to fire. We pump a few echo events to ensure the loop
            # is awake.
            for i in range(3):
                ws.send_json({"type": "session.update", "i": i})
                ws.receive_json()
            # Sleep on the real clock so the asyncio task scheduler
            # gets a chance to run the flush coroutine. The TestClient
            # runs the ASGI app in a thread, so a real sleep is the
            # right yield primitive here.
            import time as _time

            _time.sleep(0.2)

        flush_rows = [
            e
            for e in _read_entries(log)
            if e.check_name == "pipeline.realtime.flush"
        ]
        assert len(flush_rows) >= 1
        meta = flush_rows[0].metadata
        assert meta.get("interim") is True
        assert "elapsed_seconds" in meta
        assert "client_event_count" in meta
