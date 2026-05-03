# Changelog

All notable changes to signet are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/), with the understanding that
pre-1.0 minor versions may break the API.

## [Unreleased]

## [0.1.0] — 2026-05-03

First public release. Apache-2.0 OSS prior art for the gate-pattern thesis.

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

[Unreleased]: https://github.com/jeranaias/signet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jeranaias/signet/releases/tag/v0.1.0
