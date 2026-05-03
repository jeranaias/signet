# Changelog

All notable changes to signet are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/), with the understanding that
pre-1.0 minor versions may break the API.

## [Unreleased]

## [0.1.2] — 2026-05-03

### Added — UX polish from first-user smoketest

- `signet serve --dev` shorthand. Bundles `--allow-ephemeral-key`,
  `--audit-log audit.jsonl`, and `--config pipeline.py` into one
  flag. Each is only set if not otherwise specified. The most
  common local invocation drops from five flags to one.
- `signet doctor` command. Prints versions and probes endpoints:
  `--upstream <url>` checks the LLM upstream is reachable;
  `--self <url>` hits a running signet's `/health`, `/version`,
  and sends a no-owner refusal probe to confirm the gate is
  enforcing. Exits non-zero on any probe failure.
- `signet audit show <entry-id>` is the new (honest) name for what
  `signet replay` did. The `replay` alias still works but prints a
  deprecation warning; it will be removed in v0.2 alongside the
  actual pipeline-replay feature.
- `signet init` writes a `client_example.py` alongside the
  pipeline scaffold. New users no longer have to read the README
  to find out how to call signet from Python — both raw httpx and
  `wrap_openai` patterns are demonstrated.
- `signet serve` prints the ephemeral HMAC key on startup when
  `--allow-ephemeral-key` is in effect. Lets the user save it
  externally if they want to verify the audit log later instead
  of losing the key on shutdown.
- `OwnerResolutionCheck` refusal hint now lists three concrete
  header examples (`X-Commit-Owner: human:alice@example.com`,
  `X-Agent-Id: agent:nightly-syncer`, `X-Policy-Name: acme-default`)
  instead of just naming the field shapes. Refusal payload also
  carries an `examples` array.
- `X-Signet-Upstream` and `X-Signet-Upstream-Status` response
  headers on every reply so callers can finger-point upstream
  errors vs. signet errors at a glance. Configurable label via
  `--upstream-label` / `SIGNET_UPSTREAM_LABEL` (defaults to the
  upstream URL host).
- `ServerConfig.upstream_label` field exposed for embedded use.

### Documentation

- README rewritten to lead with the "why you need this now" pitch:
  three concrete attack scenarios, then the architecture, then the
  honest-scope section. Designed so a CEO can read the first three
  paragraphs and a CTO can read the rest.
- `docs/architecture.md` opens with a one-paragraph layman
  summary that names the junior-employee analogy before diving
  into the technical section. Trust model and out-of-scope
  list cleaned up.
- `docs/index.md` matches the README's framing for the docs site
  landing page.
- `docs/checks/owner_resolution.md` corrected — `X-Agent-Id`
  bare values are no longer accepted (the `agent:` prefix is
  required, fixed during pre-release security review).

## [0.1.1] — 2026-05-03

### Fixed

- `signet serve` startup banner used `→` (U+2192) which crashes Python's
  default cp1252 stdout on Windows with `UnicodeEncodeError`. Caught
  immediately on the first post-publish smoketest. Replaced with `->`
  for portability across console code pages.

## [0.1.0] — 2026-05-03

First public release. Apache-2.0 OSS prior art for the gate-pattern thesis.

### Hardened — pre-release adversarial review

Five rounds of self-review against a fresh "hater" lens before tagging,
producing ~50 fixes across the audit chain, receipt format, proxy
semantics, owner resolution, memory safety, and documentation honesty.
None are wire-format breaking; some change response semantics in ways
that match the documented intent.

#### Audit chain
- `HmacChain.append` now holds an internal `threading.Lock`; concurrent
  FastAPI requests can no longer fork the chain by reading the same
  `prev_hmac` twice. Multi-process workers still need a custom backend
  (documented).
- `_serialize_for_signing` rejects `NaN` / `Infinity` (`allow_nan=False`)
  and uses `ensure_ascii=False` so the canonical form is deterministic.
- `JsonlBackend.append` calls `os.fsync` after every write by default
  (`fsync_after_append=True`); a crash mid-handler can no longer leave
  the chain shorter than the responses already returned.
- `Key.__repr__` redacts the secret. Earlier the default dataclass repr
  would print HMAC bytes into any log line that touched a `Key`.
- Verifier docstring lists all four break kinds (`MISSING_KEY_ID` was
  missing from the module-level summary).

#### Receipts
- Receipt format now carries `alg=hmac-sha256`. The verifier rejects
  receipts whose `alg` does not match the configured signer, blocking
  downgrade attacks against future ed25519.
- `ReceiptSigner` is now a `Protocol`; concrete `HmacReceiptSigner`
  ships as the v0.1 default. Callers can pass their own signer to
  `SignetApp(receipt_signer=...)` for ed25519 or HSM-backed primitives.
- Receipt symmetry caveat called out explicitly in the module docstring,
  `SECURITY.md`, and `docs/architecture.md`.

#### Proxy semantics
- `REDACT` results from ADMISSION now actually modify the request body
  before forwarding (multimodal vision content preserved) instead of
  returning 403.
- `ESCALATE` results return `202 Accepted` with an `audit_entry_id`
  field instead of 403.
- Audit `Decision` reflects the actual outcome (BLOCK / REDACT /
  ESCALATE / ALLOW one-to-one). Earlier any non-allow collapsed to
  BLOCK in the chain.
- Inbound bodies are streamed with a configurable cap
  (`SIGNET_MAX_REQUEST_BODY_BYTES`, default 4 MiB). Anything larger
  gets a 413 before signet attempts JSON parsing.
- Empty body returns explicit 400 instead of forwarding `{}` and
  producing an opaque upstream 400.
- Pipeline crashes at admission or forward write a synthetic audit row
  before returning 500/502; earlier the chain was silent on the most
  security-relevant events.
- Streaming generator wraps in try/finally and writes a terminal audit
  row with `finish_reason="client_disconnect"` when the caller bails
  mid-stream.
- `RECORD`-stage non-allow results now persist as their own audit rows
  instead of being silently discarded.
- Sessions are now actually loaded — `_handle_chat` calls
  `session_store.get_or_create + touch` on every request that asserts
  `X-Signet-Session` and stashes the `Session` on
  `RequestContext.scratch["_session"]`. Earlier the store was wired but
  nothing populated from it.
- Unsupported OpenAI endpoints (`/v1/embeddings`, `/v1/completions`,
  `/v1/audio/*`, `/v1/images/*`) return an explicit 404 with a note,
  not FastAPI's generic body.
- `_extract_sse_content` coalesces multi-line `data:` per the
  WHATWG EventSource spec (consecutive `data:` lines join with `\n`,
  blank line dispatches the event). Matters for OpenAI-compatible
  upstreams that stream multi-line events (LiteLLM, vLLM with
  prompt-streaming).

#### Owner resolution
- Header lookup is case-insensitive and strips whitespace.
- Precedence is documented and deterministic: already-resolved →
  `X-Commit-Owner` → `X-Agent-Id` → `X-Policy-Name`. Both human and
  agent present? Human wins.
- Empty principal after a `human:` / `agent:` prefix is rejected.

#### Memory
- `InMemorySessionStore` and `InMemoryRateLimitState` are now
  LRU-bounded (defaults: 10k sessions, 50k owner buckets). An attacker
  rotating session IDs / owner identities can no longer grow the
  stores without bound.
- `ResponseContext.accumulated_text` is bounded (default 1 MiB) via
  `extend_text`. Long streams set `accumulated_text_truncated` and
  stop appending instead of doing O(N²) string growth on multi-MB
  responses.

#### Audit row contents
- `request_fingerprint` is now populated (sha256 over raw request
  bytes, computed before any redaction). All audit rows from the
  same request share this value, letting downstream tools group
  entries without inventing a request_id.
- `accumulated_text_truncated` and `chunk_count` propagate into
  `pipeline.complete` rows so consumers can flag entries where
  INSPECTION saw only a prefix.

#### Checks
- `ScopeDriftCheck` markers are now overrideable via constructor;
  empty dict disables classification drift entirely. Default
  false-positive surface documented.
- `PromptInjectionCheck` docstring lists the bypass surface
  explicitly: non-English, homoglyph (Cyrillic-lookalike),
  whitespace obfuscation, alt encodings, cross-turn attacks,
  adversarial suffixes — all known gaps.
- `SandboxResult.is_safe()` keyword list explicitly marked as a
  placeholder; users should pass a real `policy=` callable.
- `TribunalCheck.inspect_tool_call` switches to
  `gather(return_exceptions=True)` so one judge crashing no longer
  cancels the other mid-flight (which leaked the surviving HTTP
  connection and discarded a usable verdict). Reuses one
  `httpx.AsyncClient` across calls.

#### CLI
- `signet init` writes a `.gitignore` (`.env`, `.env.*`, `*.jsonl`)
  alongside the scaffold so first-time users do not commit their
  HMAC secret or audit log on push. Existing `.gitignore` is left
  alone.
- `signet serve --config <path>` prints a yellow warning that the
  flag executes arbitrary Python from the file. Function docstring
  also names it explicitly.
- `signet replay` help text is honest: it reads + prints the audit
  row but does NOT re-execute the pipeline. Replay against historical
  traffic is roadmap.
- `signet replay <UUID>` is now case-insensitive on the entry ID.
- `signet serve` prints the pipeline checks loaded at startup so
  operators can verify the configuration without reading the file.
- `_parse_hex_secret` gives a clear message when `SIGNET_HMAC_SECRET`
  is malformed: names the env var, accepts an optional `0x` prefix
  and surrounding whitespace, suggests `openssl rand -hex 32`,
  refuses secrets shorter than 16 bytes loudly.

#### SDK adapters
- `wrap_openai` / `wrap_anthropic` raise `TypeError` loudly when the
  SDK client lacks a writable `base_url`, instead of silently leaving
  the original endpoint in place.

#### Hygiene
- `_iter_entry_points` loses the pre-3.10 fallback (project pins
  `>=3.11`).

#### Threat model and supply chain
- `SECURITY.md` and `docs/architecture.md` call out two real limits up
  front: owner identity is caller-asserted (not authenticated) and the
  HMAC chain is tamper-evident (not write-once). Both have v0.2
  roadmap notes (asymmetric receipts, anchor backends).
- `SECURITY.md` reporting channel is now GitHub private security
  advisory with the gmail backed up as fallback only.
- `SECURITY.md` hardening list adds explicit `chmod 0600` guidance
  for the audit-log file (signet creates it with the OS umask).
- `publish.yml` generates a CycloneDX SBOM and attaches it to each
  GitHub Release. `SECURITY.md` commits to v0.2 sigstore + SLSA.
- README softens NIST 800-53 claim from "compatible" to "aligned with"
  and is honest about endpoint coverage (only `/v1/chat/completions`
  in v0.1).

#### New tests
- 25-thread concurrent append confirms chain stays linked.
- NaN-in-metadata confirms loud rejection.
- Custom-marker `ScopeDriftCheck` confirms override path.
- Receipt downgrade-attack confirms `alg` mismatch is rejected.
- Body too large returns 413; empty body returns 400.
- Pipeline exception writes a synthetic audit row.
- ESCALATE returns 202 with `audit_entry_id`.
- REDACT preserves vision-style image parts.
- Audit rows from the same request share `request_fingerprint`.
- `accumulated_text` truncates and flags at the cap.
- LRU eviction caps `RateLimitCheck` memory.
- Lowercase / mixed-case headers, human-wins-over-agent precedence,
  whitespace-stripped values, empty-principal blocked.
- Multi-line SSE coalescing and `[DONE]` handling.
- `_parse_hex_secret` rejects bad hex with a useful message; accepts
  whitespace + 0x prefix.
- Session loaded into `ctx.scratch["_session"]` on every request.
- `signet init` writes `.gitignore` and does not overwrite existing
  one.

Test count: 220 unit + adversarial green. mypy clean. ruff clean.

### Added — core abstractions

- `signet.core.owner.Owner` + `OwnerType` enum (human / agent / policy / unresolved)
- `signet.core.audit.AuditEntry` + `Decision` enum (allow / block / redact / escalate)
- `signet.core.check.Check` ABC + `CheckResult` with four hook timings
  (`pre_request`, `inspect_response_chunk`, `inspect_tool_call`, `post_complete`)
- `signet.core.stage.Stage` four-tier hierarchy: ADMISSION / INSPECTION / COMMITMENT / RECORD
- `signet.core.context` request / response / tool-call context dataclasses
- `signet.core.pipeline.Pipeline` fail-closed sequenced executor

### Added — HMAC audit chain

- `signet.audit.chain.HmacChain` — append-and-sign coordinator with cached prev_hmac
- `signet.audit.verifier.ChainVerifier` — distinguishes SELF_MISMATCH / LINK_MISMATCH /
  UNKNOWN_KEY / MISSING_KEY_ID break kinds
- `signet.audit.keyring.KeyRing` — multi-era key management for verification across rotations
- `signet.audit.backend.JsonlBackend` — default append-only JSONL storage
- Tamper-detection tests covering modify, delete, reorder, forge-insert, key rotation

### Added — 10 built-in checks

- `OwnerResolutionCheck` (ADMISSION) — refuse if no resolvable commit owner
- `LoopbackTrustCheck` (ADMISSION) — auto-resolve owner for loopback + Tailscale CGNAT
- `RateLimitCheck` (ADMISSION) — per-owner token bucket with pluggable state backend
- `RegexContentCheck` (ADMISSION) + `RegexOutputCheck` (INSPECTION) — block / redact patterns
- `ClassificationGateCheck` (ADMISSION) — 5-level UNCLASS → TS/SCI gate
- `PromptInjectionCheck` (ADMISSION) — pattern + heuristic + base64-decoded scan
- `TokenBudgetCheck` (ADMISSION + RECORD) — per-owner output-token quota with reconciliation
- `ScopeDriftCheck` (INSPECTION) — token / character / classification-marker drift
- `ContinuingConsentCheck` (INSPECTION) — periodic mid-stream owner-authority revalidation
- `ToolCallInspectorCheck` (COMMITMENT) — risk-tier gating + tool allowlist

### Added — HTTP proxy

- `signet.server.app.SignetApp` — FastAPI proxy with /health, /version,
  POST /v1/chat/completions
- SSE streaming with mid-stream abort + trailer event on INSPECTION block
- `signet.server.config.ServerConfig` — env-loadable runtime config
- `signet.server.session.Session` + `SessionStore` — cross-request state
- `signet.server.receipt.ReceiptSigner` — `X-Signet-Receipt` HMAC-signed
  decision summary, offline-verifiable by callers

### Added — SDK adapters

- `signet.adapters.openai.wrap_openai` — in-place reconfigure of openai SDK clients
- `signet.adapters.anthropic.wrap_anthropic` — same shape for Anthropic SDK
- `signet.adapters.langchain.SignetCallbackHandler` — LangChain-shaped observer
  surfacing receipts and refusal payloads
- 3 runnable example scripts in `examples/`

### Added — plugin interface

- `signet.plugins.discover` + `load_by_name` — entry-point-based discovery
  (group: `signet.checks`)
- `signet.plugins.tribunal.TribunalCheck` — reference dual-judge dissent
  (caller supplies judge endpoints)
- `signet.plugins.sandbox.SandboxPreviewCheck` — reference preview-before-commit
  (caller supplies sandbox runner)

### Added — CLI

- `signet serve` — run the FastAPI proxy
- `signet audit verify` — walk an HMAC-chained log and report tampering
- `signet replay` — display the audit row for a given entry ID
- `signet init` — scaffold a starter pipeline + .env

### Added — tests

- ~250 unit tests covering all 10 checks, the chain, the proxy, the adapters,
  the plugins, and the CLI
- ~25 adversarial bypass tests across 6 attack categories
- Integration suite targeting local Ollama + remote RigRun (skipped when
  endpoints not reachable)

### Added — docs

- README with one-paragraph what-it-is + quickstart
- `docs/architecture.md` covering 4-stage hierarchy, continuing-consent +
  scope-drift patterns, trust model, what is intentionally not in scope
- `docs/checks/owner_resolution.md`, `docs/checks/classification_gate.md`
- `docs/plugin_dev.md` walkthrough
- CONTRIBUTING + CODE_OF_CONDUCT + SECURITY (with explicit threat model)

### Added — CI

- Ruff lint + format + mypy --strict on every push
- Test matrix: Python 3.11 / 3.12 / 3.13 × Linux / macOS / Windows = 9 jobs per push
- mkdocs-material site builds + deploys to GitHub Pages

[Unreleased]: https://github.com/jeranaias/signet/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/jeranaias/signet/releases/tag/v0.1.2
[0.1.1]: https://github.com/jeranaias/signet/releases/tag/v0.1.1
[0.1.0]: https://github.com/jeranaias/signet/releases/tag/v0.1.0
