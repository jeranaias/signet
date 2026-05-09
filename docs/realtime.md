# WebSocket realtime API

`signet` ships a WebSocket pass-through for the OpenAI realtime API at
`/v1/realtime`. The route is auto-registered alongside the HTTP routes —
no CLI flag, no opt-in. ADMISSION runs once at connect time, COMMITMENT
runs on every function-call event in the session, RECORD writes
session-start / periodic-flush / session-end audit rows. INSPECTION
runs on text chunks; audio frames pass through unchanged with a
metadata-only audit row.

The route is unconditionally registered. FastAPI does not pre-allocate
WebSocket handlers, so deployments that never receive realtime traffic
incur no cost. Set `ServerConfig.realtime_enabled = False` when you want
a hard guarantee that the WebSocket route does not exist on a particular
deployment.

## Connection lifecycle

```
client                signet                     upstream (OpenAI realtime)
  │                     │                                  │
  │ ── WS handshake ──▶ │                                  │
  │                     │ ▶ ADMISSION (handshake headers)  │
  │                     │   refused ▶ close 1008 ◀──────── │  (no upstream
  │                     │                                  │    contact)
  │                     │   allowed ▶ session-start row    │
  │                     │             ▼                    │
  │ ◀── accept ───────── │ ── upstream WS handshake ─────▶ │
  │                     │                                  │
  │ ── client event ───▶ │ ▶ dispatch by event.type        │
  │                     │   tool call ▶ COMMITMENT         │
  │                     │     allow   ▶ forward            │
  │                     │     block   ▶ refusal back; no   │
  │                     │               forward; cancel    │
  │                     │     escalate ▶ refusal back;     │
  │                     │               approval-chain     │
  │                     │   text      ▶ INSPECTION         │
  │                     │   audio     ▶ pass-through +     │
  │                     │               audit row          │
  │                     │   other     ▶ forward            │
  │                     │                                  │
  │                     │ ── every 30s: flush row ──▶ chain│
  │                     │                                  │
  │ ◀── upstream event ─ │ ◀── upstream event ───────────── │
  │                     │                                  │
  │ ── close ─────────▶ │ ▶ session-end row                │
```

## Stages, where they run, what they see

| Stage | When | Inputs |
|-------|------|--------|
| ADMISSION | Once, at WebSocket accept. | `RequestContext` populated from the handshake headers (`X-Commit-Owner`, `X-Classification`, etc., resolved through the same case-insensitive `get_header_ci` helper the HTTP path uses). `body` is empty — handshakes have no body. |
| COMMITMENT | Every `response.function_call_arguments.done` event from upstream. | `ToolCallContext` with `tool_name`, parsed `arguments` (the realtime API ships them as a JSON-encoded string; signet parses), and `tool_metadata` (typically populated by a `ToolCallInspectorCheck` registry). |
| INSPECTION | Every text-delta event (`response.text.delta`, `response.audio_transcript.delta`). | `ResponseContext.accumulated_text` grows chunk by chunk, capped at 1 MiB the same way the streaming path does. |
| RECORD | Three triggers: connect (`pipeline.realtime.session_start`), every 30s while connected (`pipeline.realtime.flush`), and at close (`pipeline.realtime.session_end`). | Cumulative session metrics: function-call counts, event counts, audio chunks passed through, text chunks inspected, duration. |

## Audio pass-through (and why)

v0.1.6 explicitly does not run INSPECTION on audio frames. Three
reasons:

1. **Inspection requires transcription.** Per-audio-chunk INSPECTION
   means an ASR call per frame. A remote ASR call would create a
   circular dependency (the gate that protects LLM calls cannot itself
   depend on an LLM call). Local Whisper integration is the right
   long-term answer, but it's a significant new dependency we don't
   want to land in 0.1.6.
2. **Most realtime API users gate at the intent layer, not the content
   layer.** A voice agent's tool-call channel — `send_email`,
   `transfer_funds`, `delete_file` — is the same gating problem as a
   chat agent's. That's where signet adds value first.
3. **Per-frame check overhead would blow the latency budget.** Realtime
   API audio frames arrive every 20–40 ms; a synchronous check call
   per frame would overwhelm the sub-200 ms latency budget the
   protocol assumes.

Audio frames still leave a footprint in the audit chain. Each frame
gets a lightweight `pipeline.realtime.audio` row with `metadata`:

```json
{
  "session_id": "<uuid>",
  "event_type": "input_audio_buffer.append",
  "audio_inspection_skipped": true
}
```

So operators can see the *volume* of audio passing through even though
the gate has nothing to say about its content. Dashboards can plot
audio-frames-per-session over time. If you find yourself reaching for
content-level audio policy, that's the v0.1.7+ roadmap; see below.

## Function-call refusal protocol

When COMMITMENT returns BLOCK or ESCALATE, signet:

1. **Does NOT forward the function-call event** to the client. (In a
   live upstream bridge, signet also sends a synthetic
   cancellation event to the upstream so the model knows the call
   won't run.)
2. **Sends a `signet.refusal` event back to the client.** Wire shape:

   ```json
   {
     "type": "signet.refusal",
     "stage": "commitment",
     "decision": "block",
     "tool_name": "send_email",
     "call_id": "call_1",
     "correlation_id": "<entry_id>",
     "reason": "tool 'send_email' is not in the registry",
     "check": "tool_call_inspector"
   }
   ```

   Field reference:

   | Field | Type | Always present? | Notes |
   | ----- | ---- | --------------- | ----- |
   | `type` | `"signet.refusal"` | yes | Discriminator. |
   | `stage` | string | yes | `"admission"`, `"commitment"`, or `"inspection"`. |
   | `decision` | `"block"` \| `"escalate"` | yes | The pipeline result class. |
   | `tool_name` | string | when stage is `commitment` | Echoes the tool the model tried to call. |
   | `call_id` | string | when stage is `commitment` and the upstream included one | Per-call request handle from the realtime API. SDKs use this to correlate a refusal back to the specific invocation. |
   | `correlation_id` | string \| null | yes | Audit-chain entry ID. `null` when `audit_log_path` is unset. |
   | `reason` | string | yes | Coarsened to the literal `"refused"` when `strict_error_redaction` is on (the default). |
   | `check` | string | only when `strict_error_redaction` is **off** | Firing check name (`tool_call_inspector`, etc.). |
   | `approval_chain` | object | only on `decision: "escalate"` | `{"requires_approval_from": [...], "current_approver": "..."}` — the same A6 escalation routing metadata the HTTP path surfaces. |

3. SDKs should treat `signet.refusal` as a distinct event class —
   not as just another upstream event payload. Recommended client
   shape: an explicit `SignetRefusal` callback that the application
   handles separately from normal model output.

## Strict redaction

Same rule as the HTTP path. When `ServerConfig.strict_error_redaction`
is `True` (the default), the wire `reason` collapses to the literal
`"refused"` and the `check` field is omitted. `correlation_id` and
`stage` survive coarsening because they're structural — incident
response cannot pivot without them. The audit chain still records the
full reason and check name; operators recover the detail via the
correlation ID.

## Shadow-mode behavior

When `ServerConfig.shadow=True`:

* **ADMISSION refusals** close the WebSocket with code 1000 (normal)
  instead of 1008 (policy violation). Before the close, signet sends
  a `signet.shadow` event describing the would-be refusal. (Headers
  can't be set on a closed WebSocket — the JSON event is the only way
  to surface what shadow caught.) The audit row is tagged
  `metadata.shadow=true` and the
  `signet_shadow_would_have_blocked_total` counter increments.

* **COMMITMENT refusals** are converted to allow at the wire layer.
  The function-call event IS forwarded to the client. The audit row
  records the would-have-been-block (with `metadata.shadow=true`)
  and the shadow counter increments. No `signet.refusal` event ships.

* **INSPECTION refusals** on text chunks behave like the HTTP
  streaming path: the chunk passes through, the audit row tags
  `shadow=true`, the counter increments.

The whole point of shadow mode is "behavior is identical to no
signet." Surfacing a `signet.refusal` event would defeat that;
operators consult the chain via the request fingerprint. Each
WebSocket session is identified in audit rows by a stable per-session
fingerprint (`realtime-session:<uuid>`) that joins the start-row,
flush-rows, and end-row together with whatever ADMISSION /
COMMITMENT / INSPECTION rows fired during the session.

## Audit-row catalogue

Every audit row written by the realtime path carries `session_id` in
its metadata so consumers can group by session.

| `check_name` | When | Notable metadata |
|--------------|------|------------------|
| `pipeline.admission` | ADMISSION refused at connect. | Same as HTTP admission rows: firing check name, reason, owner. |
| `pipeline.realtime.session_start` | After ADMISSION allows. | `session_id`, `connected_at`. |
| `pipeline.realtime.audio` | Every audio event. | `event_type`, `audio_inspection_skipped: true`. |
| `pipeline.commitment` (allow) | Function call passed COMMITMENT. | `tool_name`, `session_id`. |
| `tool_call_inspector` (or other firing check) | Function call blocked / escalated. | `tool_name`, `session_id`, plus the firing check's own metadata (e.g. `requires_approval_from` on escalation). |
| `pipeline.inspection` | Text-chunk INSPECTION fired non-allow. | `session_id`, `chunk_count_at_block`, `abort_stage: "inspection"`. |
| `pipeline.realtime.flush` | Every 30 seconds while connected. | `session_id`, `interim: true`, all the cumulative counters. |
| `pipeline.realtime.session_end` | At WebSocket close. | `session_id`, `duration_seconds`, `function_calls_count`, `function_calls_blocked`, `function_calls_escalated`, `client_event_count`, `upstream_event_count`, `audio_chunks_passed_through`, `text_chunks_inspected`, `ended_normally`, `close_code`. |

## SDK author guidance

* Treat `signet.refusal` as a **distinct event class**. Match on
  `type === "signet.refusal"` (string literal), not on inspecting
  the `reason` field — strict redaction collapses `reason`.
* `correlation_id` is the link between the wire event and the audit
  row. Always log it where operators can grep.
* On `decision: "escalate"`, surface `approval_chain` to the
  application. The `requires_approval_from` list is the chain of
  authorities that must approve; `current_approver` is the next link.
  Your approval workflow drives off these.
* A `signet.refusal` over a tool call is **not a network error** —
  retry will not change anything. Surface it as a policy refusal.
* WebSocket close codes carry meaning:
  - `1000` — normal close, including shadow-mode neutralized refusals.
  - `1008` — policy violation, ADMISSION refused (non-shadow).
  - `1011` — internal error in the gate. Usually a pipeline crash;
    check the audit chain via the correlation ID in the matching row.

## Roadmap (deferred to v0.1.7+)

The current contract covers ADMISSION, function-call gating, text
INSPECTION, audio pass-through, and the per-session audit-row
bracket. The following realtime-specific concerns are deliberately
out of v0.1.6 and will be picked up later:

* **Audio transcription + INSPECTION on transcribed text.** Needs
  local Whisper integration design — a remote transcription call
  would be a circular dependency. Once landed, audio frames will run
  the same INSPECTION pipeline that text frames do today.
* **Interruption handling.** The realtime API lets the user interrupt
  the model mid-utterance. The current linear-stream model breaks
  here: a partial response cancelled mid-flight needs a different
  audit-row shape than a clean abort. Will need a state machine that
  tracks "what was actually delivered to the human ear" vs. "what
  the model said".
* **Latency-aware check ordering.** Skip slow checks when the
  remaining budget for the round-trip is below a threshold (e.g. 50
  ms). Today's pipeline runs every check unconditionally; a budgeted
  pipeline reorders by check timeout and skips when the budget is
  exhausted, fail-closed.
* **Live upstream bridge.** v0.1.6 ships the per-connection state
  machine and the test harness; the in-tree default loopback is
  enough for unit tests of the gate logic but does not actually
  open a connection to a real OpenAI realtime endpoint. The bridge
  is a thin override of `RealtimeHandler._send_to_client` and
  `_session_loop`; the gate logic is settled.
