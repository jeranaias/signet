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

* **ADMISSION** -- runs once, at connect time, against the WebSocket
  handshake headers. Same logic as HTTP: owner resolution,
  classification declaration, rate limit, etc. A non-allow result
  closes the WebSocket with code 1008 (POLICY_VIOLATION).
* **INSPECTION** -- runs per text-chunk, same as HTTP streaming.
  Audio frames pass through with an audit row that records
  ``audio_inspection_skipped=True``; no transcription is performed
  in 0.1.6.
* **COMMITMENT** -- runs on every function-call event the upstream
  emits. A BLOCK or ESCALATE result is NOT forwarded to the client;
  instead a synthetic refusal-status event is sent to the client and
  a synthetic cancellation event is sent to the upstream. This is the
  highest-risk surface -- a voice agent calling ``send_email`` is the
  same gating problem as a chat agent doing it.
* **RECORD** -- at session-end. Writes a cumulative-metrics row.
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
from collections.abc import Mapping
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


# Round 13 ``realtime-ws-default-deny`` closure: a UUID-shaped sanity
# check for the realtime ``call_id`` echo path. The realtime API uses
# call_id as the per-tool-call request handle and SDKs that surface it
# to operators should not be passed arbitrary upstream-controlled
# bytes (e.g. a hostile upstream stamping ``call_id="(S//NF)"`` on a
# tool call that signet then BLOCKs would cause signet itself to echo
# the marker back to the client via the refusal frame). UUIDs, hex-
# hashes, base64url IDs, and any conventional opaque identifier match
# this pattern; arbitrary text does not.
_REALTIME_CALL_ID_RE: Any = None  # lazy-compiled in _is_safe_call_id


def _is_safe_call_id(value: Any) -> bool:
    """Return True when ``value`` is a printable-token call_id.

    Accepts UUID-shape, hex-shape, base64url-shape, and similar
    structured identifiers. Refuses values that contain text outside
    ``[A-Za-z0-9_.:\\-]`` (the same charset used for
    ``X-Signet-Session`` -- a deliberate symmetry across the realtime
    + HTTP surfaces).
    """
    global _REALTIME_CALL_ID_RE
    import re as _re

    if _REALTIME_CALL_ID_RE is None:
        _REALTIME_CALL_ID_RE = _re.compile(r"^[A-Za-z0-9_.:\-]{1,256}$")
    if not isinstance(value, str):
        return False
    return bool(_REALTIME_CALL_ID_RE.match(value))


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


# Round 9 cross-domain ``realtime-ws-admission-no-session-caps``
# closure: the unary HTTP path applied the ``_MAX_SESSION_ID_BYTES``
# (256) and ``_SESSION_ID_RE`` (``[A-Za-z0-9_.:-]+``) caps before
# touching the session store, but the WebSocket admission preamble
# read the handshake's ``X-Signet-Session`` header unchecked. A 64-KB
# session ID would land in the LRU session store (10 GB exhaustion
# risk); a null-byte / control-char ID would persist verbatim into
# operator log tails. Import the canonical constants from
# :mod:`signet.server.app` so the two paths agree on the policy,
# rather than maintaining a parallel definition.
def _get_session_id_constants() -> tuple[int, Any]:
    """Lazy import to avoid an import cycle.

    :mod:`signet.server.app` imports this module's
    :class:`RealtimeHandler` from inside :meth:`SignetApp._handle_realtime`
    (also lazy); pulling the constants at module load would create a
    circular import. Defer the lookup until first use.
    """
    from signet.server.app import _MAX_SESSION_ID_BYTES, _SESSION_ID_RE

    return _MAX_SESSION_ID_BYTES, _SESSION_ID_RE


# Periodic-flush interval. Long sessions write a checkpoint row every
# this-many seconds so a crashed proxy does not lose the cumulative
# metrics for an hours-long voice session.
FLUSH_INTERVAL_SECONDS = 30.0


# OpenAI realtime API event-type constants. Kept as a small, explicit
# allowlist of the events signet treats specially; everything else
# passes through. The realtime API is still evolving -- these names are
# the v1 (October 2024) shape; future versions will add or rename events.
EVENT_FUNCTION_CALL_DONE = "response.function_call_arguments.done"
"""Upstream emits this when the model has finished assembling a tool
call's arguments. This is signet's COMMITMENT trigger."""

EVENT_AUDIO_DELTA = "response.audio.delta"
"""Upstream audio frame. Pass through with audit row only -- no
inspection in 0.1.6."""

EVENT_AUDIO_INPUT = "input_audio_buffer.append"
"""Client uploading an audio frame. Same pass-through treatment."""

EVENT_TEXT_DELTA = "response.text.delta"
"""Upstream text chunk. Run INSPECTION same as HTTP streaming."""

EVENT_AUDIO_TRANSCRIPT_DELTA = "response.audio_transcript.delta"
"""Upstream-side ASR of its own audio. Treat as text for INSPECTION
purposes -- even though it's the model's transcription of its own audio,
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

        # Cumulative session metrics -- written into the session-end
        # audit row and the periodic flush rows.
        self.client_event_count = 0
        self.upstream_event_count = 0
        self.function_calls_count = 0
        self.function_calls_blocked = 0
        self.function_calls_escalated = 0
        self.audio_chunks_passed_through = 0
        self.text_chunks_inspected = 0
        # N1 (v0.1.8.1): binary WS frames previously dropped silently.
        # Each binary frame now writes an audit row and increments this
        # counter, which surfaces in the session-end audit metadata so
        # operators can see the volume of binary traffic per session.
        self.binary_frames_received = 0

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
        events and runs the documented stage logic against them -- the
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

        Round 9 cross-domain ``realtime-ws-admission-no-session-caps``
        closure: the same ``_MAX_SESSION_ID_BYTES`` (256) and
        ``_SESSION_ID_RE`` (``[A-Za-z0-9_.:-]+``) caps the unary HTTP
        path enforces are applied here. A handshake with an oversize
        or invalid-charset ``X-Signet-Session`` header synthesizes a
        BLOCK :class:`CheckResult` keyed to ``pipeline.admission`` so
        the caller's close path runs (1008 policy violation) and an
        audit row is written.
        """
        # Header dict: starlette gives a Headers object with
        # case-insensitive lookup; coerce to a plain dict so the same
        # case-insensitive helper that HTTP uses works here too.
        headers = dict(self.websocket.headers.items())
        client_ip = self.websocket.client.host if self.websocket.client is not None else None
        session_id_raw = get_header_ci(headers, SESSION_HEADER) or None
        session_id = session_id_raw.strip() if session_id_raw else None
        if not session_id:
            session_id = None

        # Round 9: validate session-ID length + charset BEFORE the
        # session store ever sees it. Synthesize a BLOCK CheckResult
        # so the caller's existing refusal-close path (1008 with an
        # audit row) handles it exactly like a pipeline-driven block.
        # We don't touch the session store on a refused handshake.
        from signet.core.check import CheckResult as _CR

        if session_id is not None:
            max_bytes, sid_re = _get_session_id_constants()
            if len(session_id.encode("utf-8")) > max_bytes:
                # Synthesize a ctx so the refusal-handler can write
                # the audit row with realtime-shape metadata.
                self.ctx = RequestContext(
                    owner=Owner.unresolved(),
                    headers=headers,
                    body={},
                    path="/v1/realtime",
                    method="GET",
                    client_ip=client_ip,
                    # Don't index the LRU under the offending ID.
                    session_id=None,
                )
                self.ctx.scratch["_request_fingerprint"] = f"realtime-session:{self.session_id}"
                self.ctx.scratch["_realtime_session_id"] = self.session_id
                return _CR.block(
                    f"X-Signet-Session header exceeds {max_bytes} bytes",
                    _check_name="pipeline.admission",
                    _stage="admission",
                    _refusal_kind="session_id_too_long",
                    session_id_bytes=len(session_id.encode("utf-8")),
                    limit_bytes=max_bytes,
                )
            if not sid_re.match(session_id):
                self.ctx = RequestContext(
                    owner=Owner.unresolved(),
                    headers=headers,
                    body={},
                    path="/v1/realtime",
                    method="GET",
                    client_ip=client_ip,
                    session_id=None,
                )
                self.ctx.scratch["_request_fingerprint"] = f"realtime-session:{self.session_id}"
                self.ctx.scratch["_realtime_session_id"] = self.session_id
                return _CR.block(
                    "X-Signet-Session contains characters outside [A-Za-z0-9_.:-]",
                    _check_name="pipeline.admission",
                    _stage="admission",
                    _refusal_kind="session_id_invalid_charset",
                )

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
        entry = self.app._record_decision(self.ctx, result=result, check_name="pipeline.admission")

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
            with contextlib.suppress(Exception):  # pragma: no cover -- defensive
                await self.websocket.send_json(shadow_event)
            await self.websocket.close(code=WS_CLOSE_NORMAL, reason="shadow ok")
            return

        # Non-shadow: send a refusal status event for SDK ergonomics,
        # then close 1008. Carry ``decision="block"`` for parity with
        # the COMMITMENT- and INSPECTION-stage refusal frames so SDKs
        # can branch on a single field name across stages. ADMISSION
        # in 0.1.6/0.1.7 only ever blocks on the WebSocket path --
        # escalate would need an out-of-band approval workflow that
        # WS-handshake refusals can't surface -- so the decision is
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
        with contextlib.suppress(Exception):  # pragma: no cover -- defensive
            await self.websocket.send_json(refusal_event)
        # WebSocket close-reason field is capped at 123 bytes by RFC
        # 6455. Coarsen unconditionally on the wire; the audit row has
        # the full reason.
        await self.websocket.close(code=WS_CLOSE_POLICY_VIOLATION, reason="signet refused")

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
                raise WebSocketDisconnect(code=int(message.get("code", WS_CLOSE_NORMAL)))
            if mtype != "websocket.receive":
                # ``websocket.connect`` is consumed by accept(); any
                # other ASGI control message is ignored.
                continue

            self.client_event_count += 1

            # N1 (v0.1.8.1): binary WS frames were silently dropped --
            # no audit row, no counter, no pass-through. Detect them
            # explicitly BEFORE the JSON parse so they get an audit row
            # with frame size, then forward to the upstream (matching
            # the audio-event pass-through contract). Operators who
            # want to refuse binary frames can subclass and override
            # ``_handle_binary_frame``.
            binary_payload = message.get("bytes")
            if binary_payload is not None:
                await self._handle_binary_frame(binary_payload)
                continue

            event = self._parse_message(message)
            if event is None:
                # Non-JSON, non-text payload -- pass through silently
                # (the test echo doesn't synthesize a response).
                continue

            await self._dispatch_client_event(event)

    @staticmethod
    def _parse_message(
        message: Mapping[str, Any],
    ) -> dict[str, Any] | None:
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
        # Round 13 ``realtime-ws-default-deny`` closure: sanitize
        # ``call_id`` before echoing. Pre-fix any upstream-controlled
        # bytes (including classification markers) on ``event.call_id``
        # were echoed verbatim back to the client via the refusal frame
        # -- paradoxically, a BLOCK decision would leak the smuggled
        # marker via the very frame that announced the block. Validate
        # against a UUID/hex/base64url-shaped charset; replace non-
        # conforming values with the synthetic correlation_id so SDKs
        # still get a per-refusal handle without echoing hostile input.
        call_id = event.get("call_id")
        if call_id is not None:
            if _is_safe_call_id(call_id):
                payload["call_id"] = call_id
            elif entry_id is not None:
                # Fall back to the audit-row entry_id so SDK clients
                # still get a stable per-refusal handle. The full
                # offending call_id is captured in the audit metadata
                # (see ``_handle_function_call``'s ``_record_decision``
                # call) for forensics.
                payload["call_id"] = f"sanitized:{entry_id}"
            # else: chain disabled and value is unsafe -- omit
            # call_id entirely rather than echo or invent.
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

        Round 13 ``realtime-ws-default-deny`` closure: prior to v0.1.x
        this handler only inspected ``event.delta`` and forwarded every
        other sibling field (``event_id``, ``response_id``, ``item_id``,
        ``content_index``, ``output_index``, ``error.message``, any
        non-standard sibling a future API version adds) verbatim via
        ``_send_to_client``. None of those reached
        ``pipeline.inspect_response_chunk``. The same default-deny
        recursive walk the HTTP-streaming path uses is now applied to
        the full event dict so a hostile upstream that stuffs a
        classification marker into a sibling field is caught before
        the bytes reach the client. The check is done in addition to
        the ``delta``-specific inspection so the per-chunk text
        contract still drives the primary inspection path.

        Why this still matters even though the in-tree realtime is
        loopback-only: ``_recv_from_upstream`` and
        ``_forward_to_upstream`` are documented as subclass-override
        hooks for live-bridge implementations. The subclass contract
        promises ADMISSION/INSPECTION/COMMITMENT parity with the HTTP
        path; shipping a known gap that the HTTP path closed two
        rounds ago would land the gap in every live-bridge subclass.
        """
        assert self.ctx is not None
        assert self.rctx is not None

        # Lazy import to avoid an import cycle with
        # :mod:`signet.server.app`. The HTTP-streaming path's
        # recursive-walk helper is the canonical implementation; reuse
        # it so the WS path's default-deny posture and the HTTP path's
        # stay in lockstep without a parallel implementation.
        from signet.server.app import (
            _SSE_EVENT_STRUCTURAL_KEYS,
            _STRUCTURAL_ABORT,
            _collect_inspectable_strings,
            _DepthSentinelList,
            _validate_event_top_level_structural_field,
        )

        delta = event.get("delta")

        # Round 19 ``realtime-ws-uses-delta-level-skip-set-on-event-top``
        # (F-R19-1) closure: pre-fix this call passed ``_top_level=True``,
        # which activates the **delta-level** structural skip set
        # (``_SSE_DELTA_STRUCTURAL_KEYS = {role, index, id, type,
        # function_call_id, tool_call_id, stop, object, finish_reason}``).
        # But the input here is the **event** dict, not a delta dict. At
        # event scope the correct skip set is ``_SSE_EVENT_STRUCTURAL_KEYS``
        # (only ``object``), which is what the HTTP ``_SSEBuffer._flush_event``
        # path uses. The mismatch let a hostile upstream stamp a marker
        # onto ``event.type`` / ``event.id`` / ``event.stop`` /
        # ``event.tool_call_id`` / ``event.function_call_id`` /
        # ``event.object`` as a clean ASCII string -- those keys satisfied
        # the delta-level open-string validators (or routed via
        # ``_STRUCTURAL_ABORT`` for ``object`` while the abort path on
        # this WS handler was missing), the walker skipped them, and the
        # bytes forwarded to the client verbatim. Mirror the HTTP event-
        # level contract: pass ``_event_top_level=True`` so only
        # ``object`` is structural at this layer, and add the pre-walk
        # event-level abort loop (below) so a hostile wrong-VALUE in
        # ``event.object`` aborts the frame instead of slipping through.
        #
        # Run the recursive walker against the full event dict. Any
        # inspectable string reachable from a non-structural key
        # (``event_id``, ``response_id``, ``item_id``, ``error.message``,
        # ``event.type``, ``event.id``, ``event.stop``,
        # ``event.tool_call_id``, ``event.function_call_id``, etc.) is
        # fed through ``inspect_response_chunk`` so a hostile upstream
        # cannot smuggle a marker past INSPECTION via a sibling field.
        #
        # Round 15 ``realtime-walker-depth-sentinel-swallowed`` (F-R15-4)
        # closure: the HTTP path's ``_SSEBuffer._flush_event`` checks
        # ``isinstance(collected, _DepthSentinelList)`` and aborts the
        # stream via ``upstream_delta_too_deep`` (R11 closure). The R14
        # walker addition here originally treated the return as a
        # vanilla list, so an event nested deeper than ``_MAX_JSON_DEPTH``
        # (64) yielded zero sibling strings, the loop iterated zero
        # times, and the event flowed to the client unblocked. Mirror
        # the HTTP path's sentinel check: a depth-cap-tripped walker
        # result refuses the WS frame with a sanitized refusal and
        # stops forwarding.
        sibling_strings: list[str] = []
        sibling_too_deep = False
        # Round 19 (F-R19-1): mirror the HTTP path's pre-walk event-level
        # abort loop (``_SSEBuffer._flush_event``). A wrong-VALUE in an
        # event-level structural field (e.g. ``event.object="NOT.A.VALID
        # .OBJECT"``) must abort the frame as malformed rather than
        # slipping through with the marker intact.
        saw_event_structural_abort = False
        for ek, ev in event.items():
            if (
                isinstance(ek, str)
                and ek in _SSE_EVENT_STRUCTURAL_KEYS
                and _validate_event_top_level_structural_field(ek, ev) == _STRUCTURAL_ABORT
            ):
                saw_event_structural_abort = True
                break
        try:
            sibling_strings = _collect_inspectable_strings(event, _event_top_level=True)
            if isinstance(sibling_strings, _DepthSentinelList):
                sibling_too_deep = True
        except Exception:  # pragma: no cover -- walker is hardened
            logger.exception("realtime sibling-walker crashed")

        if sibling_too_deep:
            # Defense in depth: mirror the HTTP path's
            # ``upstream_delta_too_deep`` abort. Write an audit row
            # (so the failure is operator-visible), send a sanitized
            # refusal frame, and return without forwarding.
            entry = self.app._record_decision(
                self.ctx,
                result=None,
                check_name="pipeline.realtime",
                metadata={
                    "session_id": self.session_id,
                    "chunk_count_at_block": self.rctx.chunk_count,
                    "abort_stage": "inspection",
                    "abort_reason": "upstream_delta_too_deep",
                    "smuggled_via_sibling_field": True,
                },
            )
            if self.app.config.shadow:
                # Shadow mode: forward despite the would-be abort.
                await self._send_to_client(event)
                return
            refusal_too_deep: dict[str, Any] = {
                "type": "signet.refusal",
                "stage": "inspection",
                "decision": "block",
                "reason": "refused",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            await self.websocket.send_json(refusal_too_deep)
            return

        if saw_event_structural_abort:
            # Round 19 (F-R19-1) closure: mirror the HTTP path's
            # ``_SSEBuffer._flush_event`` malformed-event abort. A
            # wrong-VALUE in an event-level structural field (e.g.
            # ``event.object="NOT.A.VALID.OBJECT"``) means the frame
            # cannot be trusted at all -- it doesn't conform to the
            # documented wire contract, so any sibling string we
            # collected from it could be smuggling a marker via a key
            # the walker thought was structural. Abort the frame as
            # malformed rather than forwarding any of its bytes.
            entry = self.app._record_decision(
                self.ctx,
                result=None,
                check_name="pipeline.realtime",
                metadata={
                    "session_id": self.session_id,
                    "chunk_count_at_block": self.rctx.chunk_count,
                    "abort_stage": "inspection",
                    "abort_reason": "upstream_malformed_event",
                    "smuggled_via_sibling_field": True,
                },
            )
            if self.app.config.shadow:
                # Shadow mode: forward despite the would-be abort.
                await self._send_to_client(event)
                return
            refusal_malformed: dict[str, Any] = {
                "type": "signet.refusal",
                "stage": "inspection",
                "decision": "block",
                "reason": "refused",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            await self.websocket.send_json(refusal_malformed)
            return

        # Inspect sibling strings (everything other than ``delta``,
        # which is handled below). A non-allow result on a sibling
        # string aborts the forward via the same refusal frame the
        # delta-driven block uses.
        sibling_marker_text = None
        for s in sibling_strings:
            if delta is not None and s == delta:
                # The delta itself is walked below; skip the duplicate
                # so a single marker doesn't produce two inspection
                # rows. This is a no-op when ``delta`` is None.
                continue
            try:
                sib_result = await self.app.pipeline.inspect_response_chunk(self.rctx, s)
            except Exception as exc:
                self.app._record_exception(self.ctx, exc, check_name="pipeline.inspection")
                logger.exception("realtime sibling-field INSPECTION pipeline crashed")
                continue
            if not sib_result.is_allow:
                sibling_marker_text = s
                check_name = str(sib_result.metadata.get("_check_name", "pipeline.inspection"))
                entry = self.app._record_decision(
                    self.ctx,
                    result=sib_result,
                    check_name="pipeline.inspection",
                    metadata={
                        "session_id": self.session_id,
                        "chunk_count_at_block": self.rctx.chunk_count,
                        "abort_stage": "inspection",
                        "smuggled_via_sibling_field": True,
                    },
                )
                if self.app.config.shadow:
                    # Shadow: forward despite the would-be block; the
                    # audit row already recorded shadow=True via
                    # _record_decision (because config.shadow is True
                    # and the result is non-allow).
                    break
                refusal: dict[str, Any] = {
                    "type": "signet.refusal",
                    "stage": "inspection",
                    "decision": "block",
                    "correlation_id": entry.entry_id if entry is not None else None,
                }
                if self.app.config.strict_error_redaction:
                    refusal["reason"] = "refused"
                else:
                    refusal["reason"] = sib_result.reason
                    if check_name:
                        refusal["check"] = check_name
                await self.websocket.send_json(refusal)
                return
        # If shadow mode triggered a would-be block above, fall
        # through; the event is forwarded after delta inspection (if
        # any).
        if sibling_marker_text is not None and not self.app.config.shadow:
            # Defensive: should be unreachable -- the non-shadow
            # branch above returns.
            return

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

        refusal = {
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

    async def _handle_binary_frame(self, payload: bytes) -> None:
        """Audit + pass a binary WebSocket frame to the client (N1).

        Realtime API events are normally JSON over text frames; binary
        frames are reserved for forward compatibility (raw audio,
        opaque codec frames, etc.). Prior to v0.1.8.1 we silently
        dropped them, which left a gap in the audit trail: a misbehaving
        client could ship arbitrary bytes through the gate with no
        operator-visible record.

        This handler writes one audit row per binary frame tagged
        ``binary_frame_received=True`` and ``frame_size_bytes=N`` so
        operators can quantify the volume / size of binary traffic.
        Frames pass through to the client (mirroring the audio
        pass-through contract); subclasses that want to refuse binary
        can override this method.
        """
        assert self.ctx is not None
        self.binary_frames_received += 1
        size = len(payload) if payload is not None else 0
        self.app._record_decision(
            self.ctx,
            result=None,
            check_name="pipeline.realtime.binary",
            metadata={
                "session_id": self.session_id,
                "binary_frame_received": True,
                "frame_size_bytes": size,
            },
        )
        # Pass through to the client. Live-bridge subclasses override
        # this method if they want to push the bytes onward to a real
        # upstream rather than loopback-echoing them.
        if self.websocket.application_state is WebSocketState.DISCONNECTED:
            return
        try:
            await self.websocket.send_bytes(payload)
        except Exception:  # pragma: no cover -- defensive
            logger.exception("realtime send_bytes failed")
        self.upstream_event_count += 1

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
        in :meth:`run` so it always runs -- clean close, exception, or
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
                "binary_frames_received": self.binary_frames_received,
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
                        "binary_frames_received": self.binary_frames_received,
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
