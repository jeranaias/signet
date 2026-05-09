# Streaming abort-frame contract

When a Server-Sent Events (SSE) stream is aborted by the gate
mid-flight — by an INSPECTION-stage check or by an upstream protocol
failure — `signet` emits a single structured terminal frame so that
SDK callers can recognize the abort, attribute it, and pivot into the
audit chain via the correlation ID. The contract is part of the public
API surface: this page is what an SDK author should read before
building a streaming client against signet.

## Wire format

After the proxy has already shipped a 200 SSE handshake, an abort
emits exactly two `data:` events followed by a clean TCP close:

```
data: {"signet_abort":true,"reason":"<reason>","correlation_id":"<entry_id>","stage":"<stage>","check":"<check_name>"}

data: [DONE]

```

Field reference:

| Field            | Type           | Always present?                                 | Notes                                                                                                                                                                |
| ---------------- | -------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `signet_abort`   | `true`         | yes                                             | Discriminator. SDK code matches on this to distinguish a signet-emitted terminal frame from a normal upstream chunk that happens to carry boolean fields.            |
| `reason`         | string         | yes                                             | Human-readable explanation. Coarsened to the literal `"refused"` when `strict_error_redaction` is on (default). For upstream failures the stable token is `"upstream_protocol_violation"`. |
| `correlation_id` | string \| null | yes                                             | Audit chain entry ID for this decision. `null` when `audit_log_path` is unset. Operators pivot from the wire frame to the audit row via this ID.                     |
| `stage`          | string         | yes                                             | Pipeline stage that fired. For mid-stream blocks this is `"inspection"`; upstream failures also surface as `"inspection"` (the stage at which the failure was caught).                            |
| `check`          | string         | only when `strict_error_redaction` is **off**   | Name of the firing check (`scope_drift`, `token_budget`, etc.). Omitted under strict redaction so the wire frame does not name policy. The chain still records it.   |

The two trailing newlines after each `data:` line are intentional: SSE
event boundaries are blank-line-delimited per the WHATWG EventSource
spec.

## Strict redaction coarsening

When `ServerConfig.strict_error_redaction` is `True` (the default), the
abort frame coarsens identically to how `_refusal` coarsens 4xx response
bodies:

* `reason` collapses to the literal string `"refused"`
* `check` is omitted
* `correlation_id` and `stage` are preserved (they are structural, not
  policy-revealing — incident response cannot pivot without them)

Operators turn redaction off (`signet serve --no-strict-error-redaction`
or `signet serve --dev`) for development and integration debugging
only. Production keeps the default; the chain remains the source of
truth for the firing check and full reason.

## Worked example

Verbose mode (`strict_error_redaction=False`), `ScopeDriftCheck`
catches a classification marker mid-stream:

```
data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":" there"}}]}

data: {"signet_abort":true,"reason":"output marker '(S//NF)' implies classification level 2 > request-declared level 0","stage":"inspection","check":"scope_drift","correlation_id":"1076a04c-d0a9-4a26-8b71-3a2b21f6ad32"}

data: [DONE]

```

After the abort frame the connection closes. The two trailing newlines
are intentional (SSE event boundary).

Strict mode (default), same scenario:

```
data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-...","object":"chat.completion.chunk","choices":[{"delta":{"content":" there"}}]}

data: {"signet_abort":true,"reason":"refused","stage":"inspection","correlation_id":"1076a04c-d0a9-4a26-8b71-3a2b21f6ad32"}

data: [DONE]

```

## Shadow-mode interaction

When the proxy is configured with `shadow=True`:

* The handshake response carries the header
  `X-Signet-Shadow-Inspection-Active: 1`. SDKs should read this at
  handshake time and remember it for the duration of the stream so
  they know shadow inspection is running before the stream body
  arrives.
* INSPECTION-stage non-allow results during the stream are recorded
  in the audit chain with `metadata.shadow=true` and the
  `signet_shadow_would_have_blocked_total` counter increments.
* **No abort frame is emitted in shadow mode.** The chunk passes
  through unchanged. The whole point of shadow is that downstream
  behavior is genuinely identical to "no signet" — surfacing an
  abort frame would defeat that.
* SDKs that want to know what shadow caught during the stream consult
  the audit chain via the request fingerprint (every audit row carries
  one); there is no per-decision header on the wire because HTTP
  response headers ship before any chunk and cannot be appended
  mid-stream.

ADMISSION-stage shadow decisions DO carry per-decision headers
(`X-Signet-Shadow-*`) since they happen before the stream body — those
follow the same contract as non-streaming responses; see
[`docs/architecture.md`](./architecture.md).

## Audit log on partial delivery

When INSPECTION blocks mid-stream, the audit row's metadata captures
exactly how much of the response had been delivered:

| Field                  | Meaning                                                                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `chunks_delivered`     | Count of upstream chunks that were yielded to the client *before* the blocking chunk. The blocking chunk itself is **not** counted. |
| `chunk_count_at_abort` | Total chunks the proxy had pulled from the upstream when it decided to abort, including the blocking chunk.                          |
| `abort_stage`          | `"inspection"` for an INSPECTION-stage block, `"upstream"` for an upstream-protocol-violation/5xx abort.                            |
| `_check_name`          | Name of the firing check (`scope_drift`, `token_budget`, etc.). Always present even in strict mode — the chain is the source of truth. |

Upstream-failure aborts add:

| Field             | Meaning                                                                              |
| ----------------- | ------------------------------------------------------------------------------------ |
| `upstream_status` | The HTTP status the upstream returned (e.g. `503`).                                  |
| `reason`          | Verbatim error detail (e.g. `"upstream protocol violation: RemoteProtocolError: …"`) on the audit row's `reason` field. |

The audit row's `check_name` is `pipeline.inspection` for an
INSPECTION-stage block and `pipeline.upstream` for an upstream-failure
abort, so dashboards can filter the two cases independently.

## SDK author guidance

* Treat the `signet_abort` frame as a **distinct event class** in your
  SSE event stream — not as just another `data:` payload. Recommended
  shape: a `SignetAbort` event your client surfaces to the application
  alongside (or instead of) the partial `assistant.message`.
* Match on `signet_abort === true` (boolean), not on the `reason`
  text — strict redaction collapses `reason` and the field is the
  structural discriminator.
* `[DONE]` always follows `signet_abort` and never precedes it. If you
  receive a `signet_abort` frame, treat the next `[DONE]` as the
  expected terminator (do not treat the early termination as an
  error).
* If your client also handles upstream `[DONE]` from a successful
  stream, the `signet_abort` frame does NOT replace it — both events
  reach you in the abort path, in order: `signet_abort` first,
  `[DONE]` second.
* Always log `correlation_id` somewhere your operators can search.
  Strict mode hides the policy detail on the wire; the correlation ID
  is how the user-experience and the chain meet.
* Distinguish `reason="upstream_protocol_violation"` from a policy
  refusal in your retry strategy. Upstream failures are typically
  retriable; a policy abort is not and should surface to the user.

## Roadmap (deferred to v0.1.7)

The current contract covers outright mid-stream block, abort-on-failure,
and shadow-mode pass-through. The following stream-related concerns
are deliberately not in v0.1.6 and will be picked up in v0.1.7:

* **Token-bucket-style mid-stream throttling.** A check that wants to
  *slow* a stream rather than abort it (e.g. enforce a max-tokens-per-
  second cap to discourage prompt injection chains that race against
  monitoring). v0.1.6 has only the binary allow/abort verdict on a
  chunk; the throttle path needs a third decision shape and a coupled
  delay primitive in the proxy.
* **Per-chunk metrics histograms.** F5 already wires
  `signet_check_duration_seconds` per check call; for streams that
  means once per chunk. The histogram is correct as-is, but a per-
  *stream* aggregate (chunks/stream, bytes/stream) is not yet exposed.
  Document the existing per-chunk behavior; add the per-stream
  aggregate in 0.1.7.
* **Compression-aware streaming.** When the upstream compresses SSE
  (`Content-Encoding: gzip`), the proxy currently relies on httpx's
  default decompression so chunk inspection still operates on
  plaintext. Behavior under explicit `Accept-Encoding: identity`
  forwarding, and re-compression to the client, is not yet
  spec'd — the gate may want to enforce a no-gzip policy on the
  request side, but that policy is a separate decision from this
  contract.
