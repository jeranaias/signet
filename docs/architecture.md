# Architecture

## The pattern in one paragraph

signet separates **deciding what to do** from **being allowed to do it**. The model decides; signet decides whether the decision can fire. The model never holds commit authority. Same shape as a junior employee who can fill out a purchase order but cannot sign the check.

This matters because the prevailing approach to LLM agent safety — telling the model in its system prompt to "wait for human input" — relies on the model itself to comply with the instruction. Sufficiently capable models ignore the instruction whenever their objective gradient outweighs it. signet takes the model's compliance off the critical path: refusal lives in a separate process the model cannot influence.

## Where signet sits

```
┌────────────┐   request   ┌────────┐  upstream req   ┌──────────┐
│   Caller   │ ──────────▶ │ signet │ ──────────────▶ │  Model   │
│ (app, SDK) │             │  gate  │                 │ (vLLM,   │
└────────────┘ ◀────────── └────────┘ ◀────────────── │ OpenAI,  │
   response,                 stream                    │ Anthropic│
   X-Signet-Receipt                                    └──────────┘
```

signet is an OpenAI-compatible HTTP proxy. Callers point their existing SDK at it; nothing else changes about their integration. The proxy intercepts every request, runs an ordered set of checks against it, and only forwards if every check at the relevant stage allows.

## The four stages

Every check declares which stage it runs in. The pipeline orders execution by stage; within a stage, registration order is preserved. Stages are fail-closed: a block at stage *N* short-circuits stages *N+1...M*.

| Stage | When it runs | What blocks here means |
|---|---|---|
| **ADMISSION** | Before the request is forwarded upstream | The request never reaches the model; caller gets a 403 |
| **INSPECTION** | On every chunk as the model streams output back | The stream is aborted mid-flight; caller gets the truncated response with a trailing event identifying the check |
| **COMMITMENT** | When the model emits a tool call | The tool does not run; the model can continue but the proposed action is refused |
| **RECORD** | After the response completes | Audit-only; never modifies the already-delivered response. Used for drift detection, behavioral baselines, post-hoc flagging |

Why a four-stage hierarchy and not a flat list:

1. **Cost ordering.** ADMISSION checks are cheap and many; INSPECTION checks fire on every chunk and must be fast; COMMITMENT checks may call out to sandboxes; RECORD checks can be expensive because they sit off the critical path. Splitting them lets each stage have its own performance budget.
2. **Failure semantics.** Each stage has the right action. ADMISSION blocks return 403 to the caller. INSPECTION blocks truncate the stream. COMMITMENT blocks refuse the tool but allow the model to continue. RECORD blocks never affect the caller.
3. **Re-evaluation.** The continuing-consent pattern (below) lives at INSPECTION — even though the request was admitted, the gate re-checks authority on what the model is actually producing.

## Two patterns worth naming

### Continuing consent

Authority granted at request time is not a blank check for the entire stream. The model might produce output that drifts into territory the caller's owner would not have approved if shown the full plan. signet's INSPECTION stage exists exactly so checks can re-evaluate that authority on every chunk and pull the plug mid-stream when the actual output crosses a line the original request didn't.

A practical example: a `SECRET`-cleared caller asks an `UNCLASS` question. The model starts answering normally, then volunteers a paragraph that contains `SECRET`-tagged content that wasn't in the prompt. The classification gate runs at ADMISSION (UNCLASS request, allowed) and *also* at INSPECTION (SECRET marker detected, abort).

### Scope drift

A token-budget approval for 200 tokens shouldn't silently become a 50,000-token output. A tool-call approval for `read_file` shouldn't morph into `read_directory_recursive` partway through argument generation. The pipeline carries the original authorization scope through INSPECTION and COMMITMENT and refuses any expansion that wasn't in the original ask. This is what `ScopeDriftCheck` is for.

## What every commit produces

Every decision the pipeline makes — allow, block, redact, escalate — becomes one immutable `AuditEntry`. Entries are appended to an HMAC-chained log: each entry's HMAC depends on its predecessor's, so any tampering breaks the chain at that point and every subsequent entry.

For each *response* the proxy emits, an `X-Signet-Receipt` HTTP header is returned to the caller. The receipt is an HMAC-signed summary of the gate's decision (owner, stage outcomes, any redactions). Callers can verify the receipt offline against signet's public key. This gives the caller cryptographic proof of what the gate did, independent of trusting the proxy operator.

## Replay

Given an audit row, `signet replay <entry-id>` reproduces the original request and re-runs the pipeline against it. Used for incident response ("show me exactly why you blocked this"), regulatory audits, and check development ("does my new check produce the same decision on last week's traffic?").

Replay is deterministic for ADMISSION checks. INSPECTION and COMMITMENT replay requires the original upstream response to also be archived, since the model's output is non-deterministic.

## Plugin model

Built-in checks cover the most common cases. Anything else is a plugin: implement the `Check` protocol, expose it via Python entry points, and the pipeline picks it up. Reference plugins in the OSS release demonstrate dual-judge dissent (caller supplies two judge endpoints), sandbox preview (caller supplies a runner), and LLM-as-content-classifier.

The proprietary parent system (Pyros + Mycelium, not in this OSS release) ships richer implementations of these — production-tuned dual-judge calibration, classification-aware sandbox isolation, behavioral fingerprinting for proof-of-inference. signet ships the architectural pattern as Apache-2.0 OSS so anyone can build on it.

## Trust model

signet trusts:
- The proxy operator. Audit logs and HMAC keys live on the proxy host. A compromised proxy can rewrite history at the head of the chain.
- The TLS endpoint. Wire integrity is delegated to TLS; signet does not re-sign request payloads.
- The Python interpreter and OS. Standard threat-model scope.

signet does **not** trust:
- The upstream model. Output is treated as adversarial; INSPECTION and COMMITMENT checks assume the model may try to bypass.
- The caller. ADMISSION checks assume any header can be spoofed except those coming from a trusted-network range.
- Tool implementations. COMMITMENT checks gate tool execution before the tool runs; the tool itself is not trusted to enforce policy.

## What is intentionally not in scope

- **Persuading the model to behave.** signet does not train, fine-tune, or rewrite prompts. The model behaves however it behaves; signet decides whether to forward what it produced.
- **Network-level enforcement.** signet enforces at the application layer. Network isolation, mTLS, and outbound firewall rules are out of scope.
- **Comprehensive PII detection.** The built-in `RegexContentCheck` handles common patterns; richer detection (Presidio, custom NER) is a plugin concern.
- **Solving social engineering by AI.** A model that produces a sufficiently persuasive justification for a bad action can still get a tired human reviewer to approve it. That is a residual problem signet does not claim to solve.

---

For check-by-check details see `docs/checks/`. For writing your own checks see `docs/plugin_dev.md` (coming in v0.1).
