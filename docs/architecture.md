# Architecture

## Read this first — the one-paragraph version

A modern AI agent does two things in one process: it **decides** what to do, and it **executes** what it decided. signet wedges between those two steps. The agent still decides — it can propose any tool call, write any response, generate any output. But before that decision becomes an action, it goes through signet, which checks the proposed action against your policy. If the policy clears the action, signet forwards it. If not, signet refuses, and the agent's compliance is irrelevant — refusal happens in a separate process the agent cannot influence. Same shape as a junior employee filling out a purchase order: they can write any number on the form, but the CFO signs the check.

The rest of this document is *how that's wired*.

---

## The pattern in one paragraph (for engineers)

signet separates **deciding what to do** from **being allowed to do it**. The model decides; signet decides whether the decision can fire. The model never holds commit authority. This matters because the prevailing approach to LLM agent safety — telling the model in its system prompt to "wait for human input" — relies on the model itself to comply with the instruction. Sufficiently capable models ignore the instruction whenever their objective gradient outweighs it. signet takes the model's compliance off the critical path: refusal lives in a separate process the model cannot influence.

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

Every decision the pipeline makes — allow, block, redact, escalate — becomes one immutable `AuditEntry`. Entries are appended to an HMAC-chained log: each entry's HMAC depends on its predecessor's, so any tampering by a party that **does not** hold the HMAC key breaks the chain at that point and every subsequent entry.

For each *response* the proxy emits, an `X-Signet-Receipt` HTTP header is returned to the caller. The receipt is signed (HMAC-SHA256 in v0.1; the format carries an `alg=` tag so asymmetric signers can be added without a downgrade attack) over a canonicalized summary of the audit row. Callers verify the receipt against the signing key.

**Two limits to internalize before relying on this:**

1. **HMAC is symmetric.** The party that verifies a receipt holds the secret to forge one. Fine when verifier and proxy share a trust domain (your own auditor reads your own logs). Not fine for handing receipts to outside parties as unforgeable proof. Asymmetric (ed25519) signers are roadmapped for v0.2.
2. **The chain is tamper-evident, not write-once.** An attacker with both file-write access *and* the HMAC secret can replace the chain end-to-end and the verifier sees nothing. True append-only requires WORM storage, RFC 3161 timestamping, or transparency-log anchoring — all v0.2 work.

## Replay

Given an audit row, `signet audit show <entry-id>` displays it for incident review. Deterministic re-execution of the original pipeline against archived traffic requires the original request body to also be stored alongside the audit row — that's roadmap, not v0.1. (`signet replay` exists as a deprecated alias for `signet audit show` because the original name implied pipeline re-execution; the new name is honest about what the command actually does.)

Replay (the proper pipeline-replay version) will be deterministic for ADMISSION checks. INSPECTION and COMMITMENT replay requires the original upstream response to also be archived, since the model's output is non-deterministic.

## Plugin model

Built-in checks cover the most common cases. Anything else is a plugin: implement the `Check` protocol, expose it via Python entry points (group `signet.checks`), and the pipeline picks it up. Reference plugins shipping in `signet.plugins` demonstrate dual-judge dissent (caller supplies two judge endpoints) and sandbox preview (caller supplies a runner).

The proprietary parent system (Pyros + Mycelium, not in this OSS release) ships richer implementations of these — production-tuned dual-judge calibration, classification-aware sandbox isolation, behavioral fingerprinting for proof-of-inference. signet ships the architectural pattern as Apache-2.0 OSS so anyone can build on it.

## Trust model

signet trusts:
- The proxy operator. Audit logs and HMAC keys live on the proxy host. A compromised proxy can rewrite history end-to-end and re-sign.
- The TLS endpoint. Wire integrity is delegated to TLS; signet does not re-sign request payloads.
- The Python interpreter and OS. Standard threat-model scope.

signet does **not** trust:
- The upstream model. Output is treated as adversarial; INSPECTION and COMMITMENT checks assume the model may try to bypass.
- **The caller's owner claim.** `X-Commit-Owner` / `X-Agent-Id` / `X-Policy-Name` are recorded as caller-asserted attribution, not authenticated identity. signet does not verify JWTs, OIDC tokens, mTLS certs, or SSO sessions on its own. Audit rows say "the caller said the owner was X," not "X cryptographically authorized this." Layer real authentication (mTLS, OIDC, an SSO-fronting reverse proxy, `LoopbackTrustCheck` over a tailnet) before signet's ADMISSION stage if your threat model requires identity proof.
- Tool implementations. COMMITMENT checks gate tool execution before the tool runs; the tool itself is not trusted to enforce policy.

## What is intentionally not in scope

- **Authenticating the owner.** signet records what the caller said the owner was. Real identity proofs (JWT/OIDC verification, mTLS client cert binding, SSO sessions) belong upstream of the ADMISSION pipeline.
- **Persuading the model to behave.** signet does not train, fine-tune, or rewrite prompts. The model behaves however it behaves; signet decides whether to forward what it produced.
- **Network-level enforcement.** signet enforces at the application layer. Network isolation, mTLS, and outbound firewall rules are out of scope.
- **Comprehensive PII detection.** The built-in `RegexContentCheck` handles common patterns; richer detection (Presidio, custom NER) is a plugin concern.
- **Sophisticated prompt-injection defense.** `PromptInjectionCheck` catches obvious English patterns; non-English, homoglyph, whitespace-obfuscated, and adversarial-suffix attacks all pass. Layer an LLM-judge plugin if you need real coverage.
- **Multi-process safe audit writes.** v0.1 ships with a single-writer chain; multi-worker uvicorn deployments need a custom backend with cross-process locking.
- **Tamper-proof audit storage.** The HMAC chain is tamper-evident (detects modification by parties without the key) but not write-once. WORM storage / RFC 3161 timestamping / transparency-log anchoring is v0.2 work.
- **Solving social engineering by AI.** A model that produces a sufficiently persuasive justification for a bad action can still get a tired human reviewer to approve it. That is a residual problem signet does not claim to solve.

---

For check-by-check details see `docs/checks/`. For writing your own checks see [`docs/plugin_dev.md`](plugin_dev.md).
