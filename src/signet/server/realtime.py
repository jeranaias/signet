"""WebSocket pass-through for the OpenAI realtime API (v0.1.6).

This module hosts :class:`RealtimeHandler`, the per-connection state machine
that runs ADMISSION at WebSocket connect time, runs COMMITMENT on every
function-call event during the session, and writes per-session audit rows
(session-start, periodic flush, session-end). Audio frames pass through
unmodified with a shadow audit row tagged ``audio_inspection_skipped=True``.

The handler is split out of :mod:`signet.server.app` so the WebSocket
state machine (which is non-trivial) does not bloat the HTTP proxy
module. It receives a back-reference to the :class:`SignetApp` so it
can reuse the existing ADMISSION preamble, audit-row writer, owner
attribution headers, shadow-mode logic, and pipeline accessors. There
is **no** new audit-row shape: every row goes through the same
:meth:`SignetApp._record_decision` path that the HTTP handlers use,
so audit consumers see WebSocket sessions as just another flavor of
gated request.

Mapping signet's check stages onto a WebSocket session:

* **ADMISSION** — runs once, at connect time, against the WebSocket
  handshake headers. Same logic as HTTP: owner resolution,
  classification declaration, rate limit, etc. A non-allow result
  closes the WebSocket with code 1008 (POLICY_VIOLATION).
* **INSPECTION** — runs per text-chunk, same as HTTP streaming.
  Audio frames pass through with an audit row that records
  ``audio_inspection_skipped=True``; no transcription is performed
  in 0.1.6.
* **COMMITMENT** — runs on every function-call event the upstream
  emits. A BLOCK or ESCALATE result is NOT forwarded to the client;
  instead a synthetic refusal-status event is sent to the client and
  a synthetic cancellation event is sent to the upstream. This is the
  highest-risk surface — a voice agent calling ``send_email`` is the
  same gating problem as a chat agent doing it.
* **RECORD** — at session-end. Writes a cumulative-metrics row.
  Periodic flush rows are written every 30 seconds while connected so
  a crashed proxy does not lose hours of audit data.

Shadow-mode interaction (config.shadow=True):

* ADMISSION refusals are converted to allow + close-with-code 1000
  instead of 1008. A JSON event describing the would-be refusal is
  sent to the client BEFORE the close (response headers can't be
  added once the WebSocket is closed). Audit row stays tagged
  ``shadow=True``.
* COMMITMENT refusals are converted to allow. The function-call event
  IS forwarded; audit row tagged ``shadow=True``.
* INSPECTION shadow on text chunks works the same as HTTP streaming.

Roadmap items deliberately deferred to v0.1.7+:

* Audio transcription + INSPECTION on transcribed text (needs local
  Whisper integration design; a remote transcription call would be a
  circular dependency in a gate that protects LLM calls).
* Interruption handling (the linear-stream model breaks here; needs
  a state machine).
* Latency-aware check ordering (skip slow checks when budget < 50ms
  remaining).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from signet.core.audit import Decision
from signet.core.context import (
    RequestContext,
    ResponseContext,
    ToolCallContext,
    get_header_ci,
)
from signet.core.owner import Owner
from signet.server.session import HEADER_NAME as SESSION_HEADER

if TYPE_CHECKING:
    from signet.core.check import CheckResult
    from signet.server.app import SignetApp

logger = logging.getLogger("signet.server.realtime")


# WebSocket close codes used by the handler. Defined here so the audit
# rows and tests can refer to them by name rather than by magic number.
WS_CLOSE_NORMAL = 1000
"""Normal closure. Used for: clean session-end on both sides; ADMISSION
refusal in shadow mode (shadow neutralizes the would-be 1008)."""

WS_CLOSE_POLICY_VIOLATION = 1008
"""RFC 6455 policy-violation close. Used for ADMISSION refusal in
non-shadow mode."""

WS_CLOSE_INTERNAL_ERROR = 1011
"""Server error. Used when the proxy encounters an unexpected failure
mid-session (pipeline crash, etc.)."""


# Periodic-flush interval. Long sessions write a checkpoint row every
# this-many seconds so a crashed proxy does not lose the cumulative
# metrics for an hours-long voice session.
FLUSH_INTERVAL_SECONDS = 30.0


# OpenAI realtime API event-type constants. Kept as a small, explicit
# allowlist of the events signet treats specially; everything else
# passes through. The realtime API is still evolving — these names are
# the v1 (October 2024) shape; future versions will add or rename events.
EVENT_FUNCTION_CALL_DONE = "response.function_call_arguments.done"
"""Upstream emits this when the model has finished assembling a tool
call's arguments. This is signet's COMMITMENT trigger."""

EVENT_AUDIO_DELTA = "response.audio.delta"
"""Upstream audio frame. Pass through with audit row only — no
inspection in 0.1.6."""

EVENT_AUDIO_INPUT = "input_audio_buffer.append"
"""Client uploading an audio frame. Same pass-through treatment."""

EVENT_TEXT_DELTA = "response.text.delta"
"""Upstream text chunk. Run INSPECTION same as HTTP streaming."""

EVENT_AUDIO_TRANSCRIPT_DELTA = "response.audio_transcript.delta"
"""Upstream-side ASR of its own audio. Treat as text for INSPECTION
purposes — even though it's the model's transcription of its own audio,
the actual policy gate is ``what was emitted as text``."""


def _audio_event_types() -> frozenset[str]:
    """Event-type names that count as audio frames."""
    return frozenset({EVENT_AUDIO_DELTA, EVENT_AUDIO_INPUT})


def _text_event_types() -> frozenset[str]:
    """Event-type names that carry inspectable text content."""
    return frozenset({EVENT_TEXT_DELTA, EVENT_AUDIO_TRANSCRIPT_DELTA})


class RealtimeHandler:
    """One per WebSocket connection. Drives the full session lifecycle.

    The handler is constructed by :meth:`SignetApp._handle_realtime` and
    immediately runs :meth:`run`. It uses ``self.app`` (a back-reference
    to :class:`signet.server.app.SignetApp`) to share helpers with the
    HTTP path: audit-row writing, ADMISSION pipeline, shadow handling,
    keyring, etc. The shared helpers are the canonical path; this
    handler does not maintain a parallel implementation.
    """

    def __init__(self, app: SignetApp, websocket: WebSocket) -> None:
        self.app = app
        self.websocket = websocket
        self.session_id = str(uuid.uuid4())
        self.connected_at = time.time()
        self.ctx: RequestContext | None = None
        self.rctx: ResponseContext | None = None

        # Cumulative session metrics — written into the session-end
        # audit row and the periodic flush rows.
        self.client_event_count = 0
        self.upstream_event_count = 0
        self.function_calls_count = 0
        self.function_calls_blocked = 0
        self.function_calls_escalated = 0
        self.audio_chunks_passed_through = 0
        self.text_chunks_inspected = 0

    # ------------------------------------------------------------------
    # Top-level lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Drive ADMISSION → session loop → session-end.

        The session loop is not a real upstream-WebSocket bridge here:
        the live proxy implementation that opens a real connection to
        OpenAI's realtime endpoint is intentionally out of v0.1.6's
        scope (and would require an integration-grade test rig that
        unit tests can't cover). Instead, this loop reads client
        events and runs the documented stage logic against them — the
        bridge to a real upstream is a thin substitution that swaps
        the per-event echo for a forward to a real
        ``websockets.connect()`` upstream. Callers who want the live
        bridge today subclass :class:`RealtimeHandler` and override
        :meth:`_forward_to_upstream` / :meth:`_recv_from_upstream`;
        the in-tree default is loopback so unit tests can exercise the
        full state machine without a real upstream.
        """
        # 1. Accept the connection so we can talk to the client at all.
        #    Note: we accept BEFORE running ADMISSION because RFC 6455
        #    doesn't permit sending a body with a refused handshake; the
        #    client SDK can't read a refusal otherwise. Closing
        #    immediately after accept with code 1008 is the documented
        #    pattern.
        await self.websocket.accept()

        # 2. Run ADMISSION against the handshake headers.
        admit_result = await self._run_admission()
        if admit_result is not None:
            # ADMISSION refused. Emit a JSON event describing the
            # refusal (so SDKs see something more than an opaque close
            # code), then close with the appropriate code.
            await self._handle_admission_refusal(admit_result)
            return

        # 3. Write the session-start audit row.
        assert self.ctx is not None  # _run_admission populated it
        self._record_session_start()

        # 4. Periodic-flush task runs alongside the main session loop.
        flush_task = asyncio.create_task(self._periodic_flush())
        ended_normally = True
        close_code: int | None = None
        try:
            await self._session_loop()
        except WebSocketDisconnect as exc:
            ended_normally = True
            close_code = exc.code
        except Exception:
            # Pipeline / bridge crash during the session. Close with
            # 1011 so the SDK sees a specific signal, then write the
            # session-end audit row noting the failure.
            ended_normally = False
            close_code = WS_CLOSE_INTERNAL_ERROR
            logger.exception("realtime session crashed")
            if self.websocket.application_state is not WebSocketState.DISCONNECTED:
                with contextlib.suppress(Exception):
                    await self.websocket.close(
                        code=WS_CLOSE_INTERNAL_ERROR, reason="internal error"
                    )
        finally:
            flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await flush_task
            self._record_session_end(
                ended_normally=ended_normally,
                close_code=close_code if close_code is not None else WS_CLOSE_NORMAL,
            )

    # ------------------------------------------------------------------
    # ADMISSION (connect-time)
    # ------------------------------------------------------------------

    async def _run_admission(self) -> CheckResult | None:
        """Run ADMISSION against the handshake headers.

        Builds a :class:`RequestContext` shaped like the HTTP path's
        admit context so existing checks (OwnerResolutionCheck,
        ClassificationGateCheck, RateLimitCheck) work without any
        WebSocket-aware variants.

        Returns the firing :class:`CheckResult` on a non-allow,
        ``None`` on allow (handler should proceed to the session
        loop). Side effect: populates ``self.ctx`` so the session
        loop has the resolved owner.
        """
        # Header dict: starlette gives a Headers object with
        # case-insensitive lookup; coerce to a plain dict so the same
        # case-insensitive helper that HTTP uses works here too.
        headers = dict(self.websocket.headers.items())
        client_ip = (
            self.websocket.client.host if self.websocket.client is not None else None
        )
        session_id = get_header_ci(headers, SESSION_HEADER) or None

        # No body on a WebSocket handshake; checks that scan body
        # content (RegexContentCheck etc.) see an empty dict and
        # naturally pass.
        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body={},
            path="/v1/realtime",
            method="GET",  # WebSocket handshakes are HTTP GET
            client_ip=client_ip,
            session_id=session_id,
        )
        # Stable per-session fingerprint so audit rows can be joined
        # across the session-start / flush / session-end triple.
        ctx.scratch["_request_fingerprint"] = f"realtime-session:{self.session_id}"
        ctx.scratch["_realtime_session_id"] = self.session_id
        self.ctx = ctx

        try:
            result = await self.app.pipeline.pre_request(ctx)
        except Exception as exc:
            self.app._record_exception(ctx, exc, check_name="pipeline.admission")
            logger.exception("realtime ADMISSION pipeline crashed")
            # Treat a crash as a refusal: synthesize a block result
            # so _handle_admission_refusal does the right close.
            from signet.core.check import CheckResult as _CR

            return _CR.block(
                f"pipeline raised {type(exc).__name__}: {exc}",
                _check_name="pipeline.admission",
                _stage="admission",
            )

        if result.is_allow:
            return None
        return result

    async def _handle_admission_refusal(self, result: CheckResult) -> None:
        """Close the WebSocket per the ADMISSION refusal.

        Non-shadow: close 1008 with a coarse reason. The audit row
        still records the full detail.

        Shadow: close 1000 (normal). Send a JSON event BEFORE the
        close describing the would-be refusal so operators can see
        what shadow caught even though the connection closed cleanly.
        Headers can't be set on a WebSocket post-close so the JSON
        event is the only carrier.
        """
        assert self.ctx is not None
        entry = self.app._record_decision(
            self.ctx, result=result, check_name="pipeline.admission"
        )

        if self.app.config.shadow:
            self.app._stash_shadow_headers(self.ctx, result, entry, decision="block")
            shadow_event = {
                "type": "signet.shadow",
                "stage": "admission",
                "decision": "block",
                "would_have_closed_code": WS_CLOSE_POLICY_VIOLATION,
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            if not self.app.config.strict_error_redaction:
                shadow_event["reason"] = result.reason
                check_name = result.metadata.get("_check_name")
                if check_name:
                    shadow_event["check"] = check_name
            with contextlib.suppress(Exception):  # pragma: no cover — defensive
                await self.websocket.send_json(shadow_event)
            await self.websocket.close(code=WS_CLOSE_NORMAL, reason="shadow ok")
            return

        # Non-shadow: send a refusal status event for SDK ergonomics,
        # then close 1008. Carry ``decision="block"`` for parity with
        # the COMMITMENT- and INSPECTION-stage refusal frames so SDKs
        # can branch on a single field name across stages. ADMISSION
        # in 0.1.6/0.1.7 only ever blocks on the WebSocket path —
        # escalate would need an out-of-band approval workflow that
        # WS-handshake refusals can't surface — so the decision is
        # always ``block`` here.
        refusal_event: dict[str, Any] = {
            "type": "signet.refusal",
            "stage": "admission",
            "decision": "block",
            "correlation_id": entry.entry_id if entry is not None else None,
        }
        if self.app.config.strict_error_redaction:
            refusal_event["reason"] = "refused"
        else:
            refusal_event["reason"] = result.reason
            check_name = result.metadata.get("_check_name")
            if check_name:
                refusal_event["check"] = check_name
        with contextlib.suppress(Exception):  # pragma: no cover — defensive
            await self.websocket.send_json(refusal_event)
        # WebSocket close-reason field is capped at 123 bytes by RFC
        # 6455. Coarsen unconditionally on the wire; the audit row has
        # the full reason.
        await self.websocket.close(
            code=WS_CLOSE_POLICY_VIOLATION, reason="signet refused"
        )

    # ------------------------------------------------------------------
    # Session loop
    # ------------------------------------------------------------------

    async def _session_loop(self) -> None:
        """Read client events, dispatch by type, echo upstream-shape events.

        See :meth:`run` for why this is loopback rather than a real
        upstream bridge: a unit-test-grade contract for the realtime
        protocol is what 0.1.6 ships. The bridge to a live OpenAI
        realtime upstream is a thin override of this method.
        """
        assert self.ctx is not None
        self.rctx = ResponseContext(request=self.ctx)

        while True:
            try:
                message = await self.websocket.receive()
            except WebSocketDisconnect:
                raise
            mtype = message.get("type")
            if mtype == "websocket.disconnect":
                # Starlette's TestClient delivers disconnect this way.
                raise WebSocketDisconnect(
                    code=int(message.get("code", WS_CLOSE_NORMAL))
                )
            if mtype != "websocket.receive":
                # ``websocket.connect`` is consumed by accept(); any
                # other ASGI control message is ignored.
                continue

            self.client_event_count += 1
            event = self._parse_message(message)
            if event is None:
                # Non-JSON, non-text payload — pass through silently
                # (the test echo doesn't synthesize a response).
                continue

            await self._dispatch_client_event(event)

    @staticmethod
    def _parse_message(message: dict[str, Any]) -> dict[str, Any] | None:
        """Pull a JSON event out of the ASGI websocket.receive message.

        Realtime API events are JSON over text frames; binary frames
        carry raw audio (the ``input_audio_buffer.append`` shape uses
        base64 in JSON, so binary is reserved for forward
        compatibility). Returns ``None`` for unparseable frames.
        """
        text = message.get("text")
        if text is not None:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(obj, dict):
                return obj
            return None
        # Binary frames are not parsed in 0.1.6 (no audio inspection).
        return None

    async def _dispatch_client_event(self, event: dict[str, Any]) -> None:
        """Route a parsed client event to the appropriate stage logic.

        Function-call events run COMMITMENT. Audio events pass through
        with an audit row. Text events run INSPECTION. Other event
        types pass through unchanged with no signet-side handling.
        """
        etype = str(event.get("type", ""))

        if etype == EVENT_FUNCTION_CALL_DONE:
            await self._handle_function_call(event)
            return

        if etype in _audio_event_types():
            await self._handle_audio_passthrough(event)
            return

        if etype in _text_event_types():
            await self._handle_text_inspection(event)
            return

        # Unknown / pass-through events: increment the upstream
        # counter and echo if loopback. A live bridge would forward
        # to the upstream WebSocket here; the unit-test loopback
        # echoes so tests can confirm dispatch reached the right
        # branch.
        await self._send_to_client(event)

    # ------------------------------------------------------------------
    # COMMITMENT (function-call gating)
    # ------------------------------------------------------------------

    async def _handle_function_call(self, event: dict[str, Any]) -> None:
        """Run COMMITMENT against a proposed function call.

        Builds a :class:`ToolCallContext` shaped like the HTTP path's
        tool-call context, runs ``pipeline.inspect_tool_call``, and
        either forwards the event (allow) or sends a refusal-status
        event back to the client (block / escalate).

        Shadow mode: a non-allow result is converted to allow at the
        wire layer (the function call event IS forwarded) but the
        audit row is tagged ``shadow=True``.
        """
        assert self.ctx is not None
        assert self.rctx is not None

        self.function_calls_count += 1
        tool_name = str(event.get("name", "")) or "<unknown>"
        # Realtime API ships arguments as a JSON-encoded string in the
        # ``arguments`` field; parse so checks see structured data.
        raw_args = event.get("arguments")
        if isinstance(raw_args, str):
            try:
                arguments = json.loads(raw_args)
                if not isinstance(arguments, dict):
                    arguments = {"_raw": arguments}
            except json.JSONDecodeError:
                arguments = {"_raw": raw_args}
        elif isinstance(raw_args, dict):
            arguments = raw_args
        else:
            arguments = {}

        tcc = ToolCallContext(
            request=self.ctx,
            response=self.rctx,
            tool_name=tool_name,
            arguments=arguments,
            tool_metadata={},
        )

        try:
            result = await self.app.pipeline.inspect_tool_call(tcc)
        except Exception as exc:
            self.app._record_exception(self.ctx, exc, check_name="pipeline.commitment")
            logger.exception("realtime COMMITMENT pipeline crashed")
            # Treat as block (fail-closed) without forwarding.
            self.function_calls_blocked += 1
            await self._send_function_call_refusal(
                event,
                reason=f"pipeline raised {type(exc).__name__}",
                stage="commitment",
                check_name="pipeline.commitment",
                entry_id=None,
                decision="block",
            )
            return

        if result.is_allow:
            await self._send_to_client(event)
            self.app._record_decision(
                self.ctx,
                result=result,
                check_name="pipeline.commitment",
                metadata={"tool_name": tool_name, "session_id": self.session_id},
            )
            return

        # Non-allow: BLOCK or ESCALATE. Record the row first so the
        # refusal event can carry the correlation_id.
        check_name = str(result.metadata.get("_check_name", "pipeline.commitment"))
        entry = self.app._record_decision(
            self.ctx,
            result=result,
            check_name=check_name,
            metadata={"tool_name": tool_name, "session_id": self.session_id},
        )

        decision_label = "escalate" if result.is_escalate else "block"
        if result.is_escalate:
            self.function_calls_escalated += 1
        else:
            self.function_calls_blocked += 1

        if self.app.config.shadow:
            # Shadow: forward the event despite the would-be refusal.
            # The audit row already recorded shadow=True via
            # _record_decision (because config.shadow is True and the
            # result is non-allow).
            await self._send_to_client(event)
            return

        # Non-shadow: do NOT forward the function-call event. Send a
        # refusal-status event to the client; the synthetic
        # response.cancel goes to the upstream in a live bridge (the
        # in-tree loopback has nothing to cancel, so it's a no-op).
        await self._send_function_call_refusal(
            event,
            reason=result.reason,
            stage=str(result.metadata.get("_stage", "commitment")),
            check_name=check_name,
            entry_id=entry.entry_id if entry is not None else None,
            decision=decision_label,
            approval_chain=self._approval_chain_metadata(result),
        )

    @staticmethod
    def _approval_chain_metadata(result: CheckResult) -> dict[str, Any] | None:
        """Pull the ESCALATE approval-chain metadata from a result.

        ToolCallInspectorCheck (and similar) stamp
        ``requires_approval_from`` and ``current_approver`` on the
        result metadata so escalation routing has the chain available
        without re-deriving it. Surface those onto the wire refusal
        event when present.
        """
        meta = result.metadata
        if "requires_approval_from" not in meta and "current_approver" not in meta:
            return None
        out: dict[str, Any] = {}
        if "requires_approval_from" in meta:
            out["requires_approval_from"] = meta["requires_approval_from"]
        if "current_approver" in meta:
            out["current_approver"] = meta["current_approver"]
        return out

    async def _send_function_call_refusal(
        self,
        event: dict[str, Any],
        *,
        reason: str,
        stage: str,
        check_name: str,
        entry_id: str | None,
        decision: str,
        approval_chain: dict[str, Any] | None = None,
    ) -> None:
        """Emit the refusal-status event for a blocked/escalated call.

        Wire shape::

            {"type": "signet.refusal",
             "stage": "commitment",
             "decision": "block" | "escalate",
             "tool_name": "<name>",
             "call_id": "<echo of event.call_id when present>",
             "correlation_id": "<entry_id>",
             "reason": "<reason or 'refused' under strict>",
             "check": "<check name; omitted under strict>"}

        ``call_id`` is echoed when the upstream event included one so
        SDK clients can correlate the refusal back to the specific
        function-call attempt; the realtime API uses ``call_id`` as
        the per-tool-call request handle.

        Strict redaction coarsens ``reason`` to ``"refused"`` and
        omits ``check``, mirroring the HTTP/SSE refusal contract so
        the WebSocket wire promise is the same.
        """
        payload: dict[str, Any] = {
            "type": "signet.refusal",
            "stage": stage,
            "decision": decision,
            "tool_name": str(event.get("name", "")),
            "correlation_id": entry_id,
        }
        call_id = event.get("call_id")
        if call_id:
            payload["call_id"] = call_id
        if self.app.config.strict_error_redaction:
            payload["reason"] = "refused"
        else:
            payload["reason"] = reason
            if check_name:
                payload["check"] = check_name
        if approval_chain:
            payload["approval_chain"] = approval_chain
        await self.websocket.send_json(payload)

    # ------------------------------------------------------------------
    # INSPECTION (text chunks) and audio pass-through
    # ------------------------------------------------------------------

    async def _handle_text_inspection(self, event: dict[str, Any]) -> None:
        """Run INSPECTION on a text-delta event.

        Delegates to ``pipeline.inspect_response_chunk`` against the
        delta string. Non-allow result in non-shadow blocks the
        forward and emits a refusal-status event. Shadow mode forwards
        the chunk and tags the audit row.
        """
        assert self.ctx is not None
        assert self.rctx is not None

        delta = event.get("delta")
        if not isinstance(delta, str) or not delta:
            await self._send_to_client(event)
            return

        self.text_chunks_inspected += 1
        self.rctx.chunk_count += 1
        self.rctx.extend_text(delta)

        try:
            result = await self.app.pipeline.inspect_response_chunk(self.rctx, delta)
        except Exception as exc:
            self.app._record_exception(self.ctx, exc, check_name="pipeline.inspection")
            logger.exception("realtime INSPECTION pipeline crashed")
            return

        if result.is_allow:
            await self._send_to_client(event)
            return

        # Non-allow text inspection: same shape as HTTP streaming.
        check_name = str(result.metadata.get("_check_name", "pipeline.inspection"))
        entry = self.app._record_decision(
            self.ctx,
            result=result,
            check_name="pipeline.inspection",
            metadata={
                "session_id": self.session_id,
                "chunk_count_at_block": self.rctx.chunk_count,
                "abort_stage": "inspection",
            },
        )

        if self.app.config.shadow:
            await self._send_to_client(event)
            return

        refusal: dict[str, Any] = {
            "type": "signet.refusal",
            "stage": "inspection",
            "decision": "block",
            "correlation_id": entry.entry_id if entry is not None else None,
        }
        if self.app.config.strict_error_redaction:
            refusal["reason"] = "refused"
        else:
            refusal["reason"] = result.reason
            if check_name:
                refusal["check"] = check_name
        await self.websocket.send_json(refusal)

    async def _handle_audio_passthrough(self, event: dict[str, Any]) -> None:
        """Forward an audio event with an audit row recording the skip.

        v0.1.6 explicitly does not run INSPECTION on audio frames
        (transcription is a separate AI call; doing it here would
        create a circular dependency unless we ship local Whisper).
        Each audio frame still gets a shadow audit row so operators
        can see the *volume* of audio passing through even though the
        gate has nothing to say about its content. The tool-call
        layer (above) is the higher-priority surface.
        """
        assert self.ctx is not None
        self.audio_chunks_passed_through += 1
        # Audit row uses a lightweight metadata-only entry rather than
        # firing the pipeline; we don't want the per-frame cost of a
        # full check evaluation when no checks would do anything.
        self.app._record_decision(
            self.ctx,
            result=None,
            check_name="pipeline.realtime.audio",
            metadata={
                "session_id": self.session_id,
                "event_type": event.get("type"),
                "audio_inspection_skipped": True,
            },
        )
        await self._send_to_client(event)

    # ------------------------------------------------------------------
    # RECORD: session-start, periodic flush, session-end
    # ------------------------------------------------------------------

    def _record_session_start(self) -> None:
        """Write the session-start audit row.

        Carries the session ID, the resolved owner (so audit consumers
        can join across rows by owner) and the connect timestamp so
        downstream tooling can compute session duration without
        reading the session-end row.
        """
        assert self.ctx is not None
        self.app._record_decision(
            self.ctx,
            result=None,
            check_name="pipeline.realtime.session_start",
            metadata={
                "session_id": self.session_id,
                "connected_at": self.connected_at,
            },
        )

    def _record_session_end(self, *, ended_normally: bool, close_code: int) -> None:
        """Write the session-end audit row.

        Carries cumulative session metrics. Fires from the ``finally``
        in :meth:`run` so it always runs — clean close, exception, or
        cancellation. The shape matches what dashboards summarize
        per-session: counts of each event type and refusal class.
        """
        if self.ctx is None:
            return
        duration = time.time() - self.connected_at
        self.app._record_decision(
            self.ctx,
            result=None,
            check_name="pipeline.realtime.session_end",
            metadata={
                "session_id": self.session_id,
                "duration_seconds": round(duration, 3),
                "function_calls_count": self.function_calls_count,
                "function_calls_blocked": self.function_calls_blocked,
                "function_calls_escalated": self.function_calls_escalated,
                "client_event_count": self.client_event_count,
                "upstream_event_count": self.upstream_event_count,
                "audio_chunks_passed_through": self.audio_chunks_passed_through,
                "text_chunks_inspected": self.text_chunks_inspected,
                "ended_normally": ended_normally,
                "close_code": close_code,
            },
        )

    async def _periodic_flush(self) -> None:
        """Emit a checkpoint audit row every FLUSH_INTERVAL_SECONDS.

        Runs as a background task for the duration of the session.
        Each checkpoint is a non-decision audit row carrying the same
        cumulative metrics shape as session-end. If the proxy crashes
        before session-end can run, downstream audit consumers still
        see how far the session got via the most recent flush row.
        """
        try:
            while True:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                if self.ctx is None:
                    continue
                self.app._record_decision(
                    self.ctx,
                    result=None,
                    check_name="pipeline.realtime.flush",
                    metadata={
                        "session_id": self.session_id,
                        "elapsed_seconds": round(time.time() - self.connected_at, 3),
                        "function_calls_count": self.function_calls_count,
                        "function_calls_blocked": self.function_calls_blocked,
                        "function_calls_escalated": self.function_calls_escalated,
                        "client_event_count": self.client_event_count,
                        "upstream_event_count": self.upstream_event_count,
                        "audio_chunks_passed_through": self.audio_chunks_passed_through,
                        "text_chunks_inspected": self.text_chunks_inspected,
                        "interim": True,
                    },
                )
        except asyncio.CancelledError:
            return

    # ------------------------------------------------------------------
    # Wire helpers
    # ------------------------------------------------------------------

    async def _send_to_client(self, event: dict[str, Any]) -> None:
        """Forward an event back to the client.

        In a live-upstream bridge this is the upstream→client leg. In
        the in-tree loopback, this echoes so unit tests can observe
        which events were forwarded vs. which were withheld by a
        refusal. Subclasses that bridge to a real upstream override
        this and :meth:`_recv_from_upstream`.
        """
        self.upstream_event_count += 1
        if self.websocket.application_state is WebSocketState.DISCONNECTED:
            return
        try:
            await self.websocket.send_json(event)
        except Exception:
            logger.exception("realtime send_json failed")  # pragma: no cover


# Mark Decision import as used so linters don't strip it; keeping it
# around means future hooks (e.g. converting result.decision values)
# don't have to re-import.
_ = Decision
