"""Round 19 hunt closures — regression coverage for F-R19-* findings.

This file accumulates regression tests for the Round-19 SERVER +
STREAMING hunt findings:

HIGH:

- ``F-R19-1 realtime WS walker uses delta-level structural skip set on
  event-top``: ``RealtimeHandler._handle_text_inspection`` called
  ``_collect_inspectable_strings(event, _top_level=True)`` against the
  **event** dict. ``_top_level=True`` activates the **delta-level**
  skip set (``role``, ``index``, ``id``, ``type``, ``function_call_id``,
  ``tool_call_id``, ``stop``, ``object``, ``finish_reason``), which let
  a hostile upstream stamp a marker into ``event.type`` / ``event.id``
  / ``event.stop`` / ``event.tool_call_id`` / ``event.function_call_id``
  as a clean ASCII string. The validator's open-string contract for
  those keys at delta scope let the value pass, the walker skipped it,
  and the bytes forwarded to the client verbatim. The HTTP path's
  ``_SSEBuffer._flush_event`` correctly uses ``_event_top_level=True``
  (only ``object`` is structural at event scope) and adds a pre-walk
  event-level abort loop for wrong-VALUE in ``event.object``. Post-fix
  the realtime path mirrors both behaviors.

LOW:

- ``F-R19-2 pool keepalive ratio not sanity-checked``:
  ``upstream_pool_max_keepalive_connections >
  upstream_pool_max_connections`` was silently accepted; httpx clamps
  the keepalive cap to ``max_connections`` so the operator's intended
  value is quietly ignored. Post-fix a cross-field check in
  ``__setattr__`` (both directions) and ``__post_init__`` (constructor
  path) rejects the mis-config at the assignment / construction line.
"""

from __future__ import annotations

import asyncio
import json as _json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from signet.core.check import Check, CheckResult, Stage
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.server.app import SignetApp
from signet.server.config import ServerConfig
from signet.server.realtime import RealtimeHandler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_MARKER = "(S//NF)"
"""Sample classified marker used by the smuggle probes."""


class _PerChunkMarkerBlock(Check):
    """INSPECTION-stage check that blocks any chunk *literally* containing
    the marker.

    Differs from ``RegexOutputCheck`` (which scans
    ``ctx.accumulated_text``) by inspecting the per-call ``chunk``
    argument directly. The realtime sibling-walker invokes
    ``pipeline.inspect_response_chunk(self.rctx, s)`` once per collected
    sibling string but does NOT extend ``accumulated_text`` for sibling
    strings (only ``delta`` extends accumulated text). A check that
    relies on ``accumulated_text`` would not fire on sibling strings;
    this per-chunk check is the right granularity for proving sibling
    strings reach inspection.
    """

    name = "per_chunk_marker_block"
    stage = Stage.INSPECTION

    async def inspect_response_chunk(self, ctx: ResponseContext, chunk: str) -> CheckResult:
        if _MARKER in chunk:
            return CheckResult.block("classified marker present in chunk")
        return CheckResult.allow()


def _build_handler(tmp_path: Path) -> tuple[RealtimeHandler, MagicMock]:
    """Construct a ``RealtimeHandler`` primed for direct
    ``_handle_text_inspection`` invocation.

    Returns the handler and the mocked WebSocket so tests can assert
    against ``send_json`` calls. The pipeline holds a single per-chunk
    marker block so the smuggle paths actually fire a block when the
    walker reaches the marker.
    """
    cfg = ServerConfig(
        upstream_url="http://upstream-mock/v1",
        allow_ephemeral_key=True,
        audit_log_path=tmp_path / "audit.jsonl",
        strict_error_redaction=True,
    )
    pipeline = Pipeline(checks=[_PerChunkMarkerBlock()])
    app = SignetApp(config=cfg, pipeline=pipeline)
    websocket = MagicMock()
    websocket.send_json = AsyncMock()
    websocket.application_state = MagicMock()

    handler = RealtimeHandler(app, websocket)
    handler.ctx = RequestContext(
        owner=Owner.unresolved(),
        body={},
        headers={},
        method="GET",
        path="/v1/realtime",
    )
    handler.rctx = ResponseContext(request=handler.ctx)
    handler.session_id = "test-session-r19"
    return handler, websocket


# ---------------------------------------------------------------------------
# HIGH -- F-R19-1 realtime WS uses wrong structural skip set
# ---------------------------------------------------------------------------


class TestF_R19_1_RealtimeWalkerEventLevelSkipSet:
    """End-to-end WS frames with the marker smuggled into an event-level
    sibling field that the delta-level structural skip set lets through.
    Each must produce a refusal frame -- NOT a forwarded event.

    The pre-fix code path called ``_collect_inspectable_strings(event,
    _top_level=True)``; the post-fix code uses ``_event_top_level=True``
    plus a pre-walk event-level abort loop mirroring the HTTP path.
    """

    @pytest.mark.parametrize(
        "smuggle_field",
        [
            "type",
            "id",
            "stop",
            "tool_call_id",
            "function_call_id",
        ],
    )
    def test_marker_in_event_sibling_blocked(self, tmp_path: Path, smuggle_field: str) -> None:
        """Each of these keys is in ``_SSE_DELTA_STRUCTURAL_KEYS`` (the
        pre-fix skip set) but NOT in ``_SSE_EVENT_STRUCTURAL_KEYS`` (the
        correct event-level set). Pre-fix the walker skipped them and the
        marker forwarded verbatim. Post-fix the walker collects the
        sibling, INSPECTION fires, and a refusal frame is sent."""
        handler, websocket = _build_handler(tmp_path)

        event: dict[str, Any] = {
            "type": "response.text.delta",
            "delta": "innocuous text",
        }
        # Override the smuggle field with the marker. ``type`` legitimately
        # routes the event so we need to keep it shaped like a text event;
        # for the ``type`` smuggle case we overwrite with the marker --
        # post-fix this is caught (open-string validator at delta scope
        # would have skipped it, but event-scope walks it).
        event[smuggle_field] = _MARKER

        asyncio.run(handler._handle_text_inspection(event))

        # A refusal frame was sent.
        assert websocket.send_json.called, f"no refusal frame for smuggle in event.{smuggle_field}"
        # No bytes containing the marker reached the client. Strict
        # redaction is on so the refusal payload should not echo the
        # marker; more importantly the original event was NOT forwarded.
        for call in websocket.send_json.call_args_list:
            payload = call.args[0]
            assert _MARKER not in _json.dumps(payload), (
                f"marker leaked in event.{smuggle_field}: {payload!r}"
            )
            # The handler must have emitted a signet refusal frame, not
            # the original event echoed back.
            assert payload.get("type") == "signet.refusal", (
                f"unexpected payload for event.{smuggle_field}: {payload!r}"
            )

    def test_marker_in_event_object_aborts_via_malformed_path(self, tmp_path: Path) -> None:
        """``event.object`` is the one key that's structural at BOTH
        scopes, but with different enums. At event scope a marker value
        is not in ``_SSE_EVENT_OBJECT_VALUES`` so the event-level abort
        loop fires (mirrors HTTP path). Pre-fix the realtime handler had
        no event-level abort loop AND used the delta-level skip set
        (which validates ``object`` as open-string at delta scope), so
        the value was skipped entirely. Post-fix the abort path fires
        and a refusal frame is sent without forwarding the event."""
        handler, websocket = _build_handler(tmp_path)

        event = {
            "type": "response.text.delta",
            "object": _MARKER,
            "delta": "innocuous text",
        }

        asyncio.run(handler._handle_text_inspection(event))

        assert websocket.send_json.called, "no refusal frame for event.object"
        payload = websocket.send_json.call_args.args[0]
        assert payload.get("type") == "signet.refusal"
        assert _MARKER not in _json.dumps(payload), (
            f"marker leaked in event.object refusal: {payload!r}"
        )

    def test_marker_in_event_object_shadow_mode_forwards_with_audit(self, tmp_path: Path) -> None:
        """In shadow mode the would-be abort is neutralized and the
        event IS forwarded, mirroring the HTTP-path shadow contract.
        An audit row still records the would-be abort."""
        cfg = ServerConfig(
            upstream_url="http://upstream-mock/v1",
            allow_ephemeral_key=True,
            audit_log_path=tmp_path / "audit.jsonl",
            strict_error_redaction=True,
            shadow=True,
        )
        pipeline = Pipeline(checks=[_PerChunkMarkerBlock()])
        app = SignetApp(config=cfg, pipeline=pipeline)
        websocket = MagicMock()
        websocket.send_json = AsyncMock()
        websocket.application_state = MagicMock()
        handler = RealtimeHandler(app, websocket)
        handler.ctx = RequestContext(
            owner=Owner.unresolved(),
            body={},
            headers={},
            method="GET",
            path="/v1/realtime",
        )
        handler.rctx = ResponseContext(request=handler.ctx)
        handler.session_id = "test-session-r19-shadow"

        event = {
            "type": "response.text.delta",
            "object": "NOT.A.VALID.OBJECT",
            "delta": "innocuous text",
        }

        asyncio.run(handler._handle_text_inspection(event))

        # Shadow forwards the event (no refusal frame is sent in its
        # place). The handler should have invoked send_json with the
        # original event shape (loopback echo).
        assert websocket.send_json.called
        payload = websocket.send_json.call_args.args[0]
        # In shadow mode we should NOT see a refusal frame here.
        assert payload.get("type") != "signet.refusal", (
            f"shadow mode unexpectedly refused: {payload!r}"
        )

    def test_clean_event_still_forwards(self, tmp_path: Path) -> None:
        """A clean event with no marker forwards normally. Regression
        guard: the fix must not change the happy-path behavior."""
        handler, websocket = _build_handler(tmp_path)

        event = {
            "type": "response.text.delta",
            "id": "evt_abc123",
            "delta": "hello world",
        }

        asyncio.run(handler._handle_text_inspection(event))

        # Loopback echoes the clean event back to the client; no
        # refusal frame.
        assert websocket.send_json.called
        payload = websocket.send_json.call_args.args[0]
        assert payload.get("type") == "response.text.delta"
        assert payload.get("delta") == "hello world"


# ---------------------------------------------------------------------------
# LOW -- F-R19-2 pool keepalive ratio not sanity-checked
# ---------------------------------------------------------------------------


class TestF_R19_2_PoolKeepaliveRatio:
    """``upstream_pool_max_keepalive_connections`` must be
    ``<= upstream_pool_max_connections``; httpx silently clamps the
    keepalive cap to ``max_connections``, so the larger value is a
    hidden mis-config. Cross-field check fires at the assignment line
    AND at construction."""

    def test_setattr_keepalive_above_max_rejected(self) -> None:
        """Defaults are max=100 / keepalive=20. Raising keepalive past
        max (200 > 100) must be rejected at the assignment line."""
        cfg = ServerConfig()
        with pytest.raises(ValueError, match="must be <="):
            cfg.upstream_pool_max_keepalive_connections = 200

    def test_setattr_lowering_max_below_keepalive_rejected(self) -> None:
        """The symmetric direction: lowering ``max_connections`` below
        the existing ``keepalive`` cap is the same hidden mis-config."""
        cfg = ServerConfig()
        # Defaults: max=100, keepalive=20. Raise keepalive to 50.
        cfg.upstream_pool_max_keepalive_connections = 50
        # Now try to lower max below 50.
        with pytest.raises(ValueError, match="must be >="):
            cfg.upstream_pool_max_connections = 10

    def test_constructor_keepalive_above_max_rejected(self) -> None:
        """Construction path: dataclass-generated assignments happen
        before ``_post_init_done``, so ``__setattr__`` doesn't fire the
        cross-field check. ``__post_init__`` covers the constructor."""
        with pytest.raises(ValueError, match="must be <="):
            ServerConfig(
                upstream_pool_max_connections=10,
                upstream_pool_max_keepalive_connections=50,
            )

    def test_equal_values_accepted(self) -> None:
        """``keepalive == max`` is the boundary -- accepted. httpx
        treats them as equal pools (every connection is keepalive-
        eligible)."""
        cfg = ServerConfig(
            upstream_pool_max_connections=50,
            upstream_pool_max_keepalive_connections=50,
        )
        assert cfg.upstream_pool_max_connections == 50
        assert cfg.upstream_pool_max_keepalive_connections == 50

    def test_default_values_round_trip(self) -> None:
        """Defaults (100 / 20) must continue to work. Regression guard."""
        cfg = ServerConfig()
        assert cfg.upstream_pool_max_connections == 100
        assert cfg.upstream_pool_max_keepalive_connections == 20

    def test_keepalive_below_max_via_setattr_accepted(self) -> None:
        """Routine tuning: keepalive set below max should still work."""
        cfg = ServerConfig()
        cfg.upstream_pool_max_connections = 200
        cfg.upstream_pool_max_keepalive_connections = 50
        assert cfg.upstream_pool_max_connections == 200
        assert cfg.upstream_pool_max_keepalive_connections == 50

    def test_error_message_names_both_fields(self) -> None:
        """The error message must name BOTH fields so operators can
        find the assignment line without grepping."""
        with pytest.raises(ValueError) as excinfo:
            ServerConfig(
                upstream_pool_max_connections=10,
                upstream_pool_max_keepalive_connections=50,
            )
        msg = str(excinfo.value)
        assert "upstream_pool_max_connections" in msg
        assert "upstream_pool_max_keepalive_connections" in msg
