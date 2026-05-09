# Changelog

All notable changes to signet are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [SemVer](https://semver.org/), with the understanding that
pre-1.0 minor versions may break the API.

## [Unreleased]

## [0.1.6] — 2026-05-07

### The architectural-stretch release — bug fixes, the marquee feature, plus six P3 items at ship-in-0.1.6 scope

Three release candidates (`v0.1.6-rc1` through `v0.1.6-rc3`) staged
the work over the sprint window so each chunk got soak time on PyPI
before the final tag. Final tag includes all of P0, P1, P2, and the
ship-in-0.1.6 boundary of P3.

### Fixed (P0)

- **B1**: `Owner.create(type="human")` previously did not coerce string
  inputs to the `OwnerType` enum, leaving `owner.owner_type` as a raw
  string and breaking downstream `is OwnerType.HUMAN` checks. Now
  routed through a new `_coerce_owner_type` helper that accepts the
  enum, lowercase, uppercase, and Title Case strings; invalid strings
  raise `ValueError` with the list of valid values.
- **B2**: `KeyRing(keys={"k1": b"x" * 32}, active_id="k1")` previously
  stored raw bytes instead of `Key` instances, causing
  `kr.active.key_id` to raise `AttributeError`. The dict-shape
  constructor now wraps bytes values into `Key` before falling through
  to the list-handling path.
- **B3**: New `tests/unit/test_constructor_aliases.py` parametrizes
  every public constructor over its accepted input forms (24 cases).
  Both bugs above slipped through 262 unit tests in v0.1.5 because
  coverage only exercised canonical typed inputs; this test file
  catches the next alias drift.

### Added (P1 polish)

- **F1 — `--shadow` mode** *(the marketing-leverage feature)*. Run
  signet in non-enforcing pilot mode: pipeline runs, audit chain
  records every decision with `metadata.shadow=True`, metrics fire,
  but block / escalate / redact decisions are neutralized at the
  response layer. The would-be refusal is surfaced to the caller as
  response headers (`X-Signet-Shadow-Decision`, `-Reason`, `-Stage`,
  `-Check`, plus `X-Signet-Correlation-Id`). New
  `signet_shadow_would_have_blocked_total` Prometheus counter tracks
  the would-be refusal rate during pilots. `/health` body gains
  `"shadow": true` when shadow is on. `--shadow` /
  `SIGNET_SHADOW=1` / `ServerConfig.shadow=True` to enable.
- **F2 — `signet replay <correlation_id>`** promoted to first-class.
  Takes the correlation_id from a 403 / 202 response (the only field
  exposed under strict redaction) and pretty-prints the full audit
  row, including HMAC verification against the configured key.
  `signet audit show` continues to work as the canonical alias.
- **F3 — Case-insensitive header sweep** via a new `get_header_ci`
  helper in `signet.core.context`. Production traffic from reverse
  proxies that normalize headers differently (uvicorn lowercases,
  nginx may preserve case) no longer silently misses lookups. 29 new
  parametrize cases cover `X-Classification`, `X-Commit-Owner`,
  `X-Agent-Id`, `X-Policy-Name` across canonical / lowercase /
  uppercase variants.
- **F4 — Three-state `audit_chain_head_hmac`** on `/health`:
  `"disabled"` (no audit configured), `null` (configured but empty),
  or 8-hex-char tail (has entries). Monitoring can distinguish
  "alive but no audit" from "alive but chain not yet written to."
- **F5 — Per-check latency histograms**. New
  `signet_check_duration_seconds{check, stage, decision}` Prometheus
  histogram. Pipeline wraps every check hook
  (`pre_request`, `inspect_response_chunk`, `inspect_tool_call`,
  `post_complete`) in a `perf_counter` timer. Timeouts map to
  `decision=block`. Optional dependency: `Pipeline` without metrics
  observer just skips observation.
- **F6 — `signet lint` SIG001 repurposed** for explicit
  `RateLimitCheck.priority` overrides below the default 100. The
  original SIG001 was made moot by v0.1.5's
  `RateLimitCheck.priority=100` default; the rule now catches plugin
  authors / pipeline hand-edits that recreate the v0.1.4 footgun
  (rate limits draining on downstream-blocked requests).

### Added (P2 nice-to-haves)

- **N1 — `signet doctor --probe-injection`**. New flag on the
  existing doctor command. Sends a 9-payload corpus of obfuscated
  injection attempts (cyrillic confusable, stretched whitespace,
  base64, ROT13, base32, hex, DAN persona, etc.) to `--self` and
  asserts every one is blocked. Catches "someone mis-edited the rule
  list" regressions in CI. Corpus lives at
  `signet.cli_helpers.probe_injection_corpus` for reuse.
- **N2 — `signet_response_text_truncated_total` counter**. Increments
  the first time `ResponseContext.accumulated_text_cap` is hit per
  response. INSPECTION-stage drift checks scanning a prefix instead
  of the full output is now visible in Prometheus.
- **N3 — `--upstream-label` round-trip integration test**. Locks in
  the chain from CLI flag → `ServerConfig.upstream_label` →
  `X-Signet-Upstream` response header on success, refusal, and
  escalation paths. `/health`, `/healthz`, `/version`, `/readyz`
  correctly omit the header.
- **N4 — Multi-worker rate-limit caveat documented** in
  `docs/deploying.md`. Default in-process bucket store means
  `uvicorn --workers N>1` gives effective per-owner rate limit of N×
  configured. Bundled `RedisRateLimitState` documented as the
  strict-limit fix.

### Added (P3 architectural stretch — ship-in-0.1.6 boundary)

- **A1 — Plugin entry-point convention + ABI versioning**. Third-
  party `Check` authors register against
  `[project.entry-points."signet.checks"]`. New
  `signet.plugins.discover_plugins()` walks
  `signet.checks` / `signet.adapters` / `signet.anchors` groups and
  returns a structured `DiscoveredPlugin` list with status per
  entry (`loaded`, `incompatible_abi`, `load_error`).
  `signet.core.check.CHECK_ABI_VERSION = 1` anchors plugin ABI
  compatibility going forward. New `signet plugins list` CLI
  surfaces the discovery report. Spec at `docs/plugin-authors.md`.
  Deferred to 0.1.7: hot-reload, plugin-supplied lint rules,
  plugin-supplied report formats.
- **A2 — Audit log compaction with Merkle archival**. JSONL chains
  grow unboundedly; this adds happy-path compaction that archives
  old ranges while preserving end-to-end verifiability.
  `signet audit compact --before <ts> --output <archive>` builds a
  SHA-256 Merkle tree over the entries, writes a byte-stable archive
  (header + Merkle tree + gzip JSONL), and replaces the compacted
  range in the live log with a single HMAC-chained compaction
  marker. `signet audit verify --including-archives <dir>` walks
  live log + every referenced archive and reports `MERKLE_MISMATCH`
  / `ARCHIVE_MISSING` / `ARCHIVE_FORMAT_INVALID` breaks alongside
  the existing kinds. Spec at `docs/audit-archive-format.md`.
  Deferred to 0.1.7: concurrent-write safety (chain MUST be
  quiesced; documented in three places and enforced via
  `--quiesce-confirm`), partial-compaction recovery,
  encryption-at-rest, sub-range incremental verification.
- **A3 — Streaming abort-frame contract**. Drove an SSE stream
  end-to-end through the proxy for the first time at v0.1.6 RC and
  the test harness surfaced 5 real bugs in the existing streaming
  path. All fixed: discriminator key was `signet_aborted` not
  `signet_abort` (wire spec mismatch), abort frame missed
  `correlation_id` and `stage`, no strict-redaction coarsening, no
  audit row for partial state on mid-stream block, malformed
  upstream / 5xx mid-stream emitted nothing. Now standardized: the
  abort frame is `{"signet_abort":true,"reason":...,"correlation_id":...,"stage":...,"check":...}`
  followed by `data: [DONE]`. Strict redaction collapses `reason` to
  `"refused"` and omits `check`. Spec at `docs/streaming.md`.
- **A4 — `signet audit report --since <duration>`**. Daily / weekly
  markdown summary suitable for direct paste into incident review.
  Aggregates by decision distribution, top firing checks, top
  blocked owners (anonymized by default via SHA-256 of
  `salt:owner_id`). Shows deltas vs prior period. Includes audit-
  chain integrity check + head HMAC tail. `--format json` for
  programmatic consumers; `--no-anonymize` for authorized roles.
  Salt comes from `SIGNET_ANONYMIZE_SALT` or `--anonymize-salt`.
  Deferred to 0.1.7: HTML output with sparklines, time-series export
  to Prometheus / Datadog, auto-cron emission to Slack / webhooks.
- **A5 — WebSocket / OpenAI realtime API support**. Pass-through proxy
  at `/v1/realtime`. ADMISSION runs at handshake, COMMITMENT runs on
  every function-call event in the session (the highest-risk surface
  for voice agents — `send_email` / `delete_file` from voice is the
  same gating problem as from chat), INSPECTION runs on text content
  events only (audio passes through with audit row tagged
  `metadata.audio_inspection_skipped=True`), RECORD writes
  session-start / session-end rows with cumulative session metadata
  plus periodic 30-second interim flushes so a crash doesn't lose
  hours of audit data. Refusal events use a structured
  `signet.refusal` shape that SDK callers can parse. Spec at
  `docs/realtime.md`. Deferred to 0.1.7+: audio transcription +
  INSPECTION on transcribed text (needs local Whisper integration
  design), interruption handling (linear-stream model breaks here),
  latency-aware check ordering.
- **A6 — `Owner.approval_chain` surface in COMMITMENT escalation**.
  When `ToolCallInspectorCheck` escalates an irreversible high-tier
  tool call, the audit row now carries
  `requires_approval_from` (full ordered approval chain) and
  `current_approver` (first link, or `None`) so downstream approval
  workflows can route without re-deriving them. Spec at
  `docs/escalation.md`. Deferred to 0.1.7: `signet escalation
  pending|approve|deny` subcommand suite, multi-step chain walking,
  webhook config, timeout / auto-deny policy.

### Changed

- `RateLimitCheck` no longer rejects `priority < 100` at construction;
  `signet lint` SIG001 surfaces it as a warning instead so authors
  who genuinely need pre-content rate limiting can opt in.
- The Knowledge of which check fired (the `_check_name` metadata key)
  on every `CheckResult` continues to flow through the pipeline; the
  new abort-frame contract surfaces it in shadow / streaming response
  envelopes alongside the strict-redaction-mode `correlation_id`.

### Tests

- 262 unit tests at v0.1.5 → 418 at v0.1.6. Phase-by-phase: rc1 added
  parametrize sweep + header case variants + 3-state health + per-
  check latency histograms + escalation metadata coverage; rc2 added
  shadow mode (6) + truncation counter (9) + upstream-label round-
  trip (5); rc3 added plugin discovery (5) + audit compaction (21) +
  CLI sweep (19); final tag added streaming abort harness (8) +
  WebSocket realtime (8).

## [0.1.5] — 2026-05-06

### Operator-day-one polish — 13 items from the v0.1.4 evaluation pass

A targeted round of fixes and ergonomic upgrades aimed at the
friction operators hit on first integration. No new check shipped;
no public-API renames; existing `pipeline.py` files continue to work
unchanged.

### Added

- **`signet lint pipeline.py`** subcommand. Static analysis on a
  configured pipeline. Catches the four most common
  misconfigurations: missing `OwnerResolutionCheck` (SIG002),
  rate-limit ordered before content checks (SIG001),
  `ToolCallInspectorCheck(allow_unregistered=True)` (SIG003),
  `ClassificationGateCheck` without a paired INSPECTION-stage
  `ScopeDriftCheck` (SIG004). `--strict` promotes warnings to a
  non-zero exit for CI invocations.
- **`/healthz` and `/readyz` endpoints**. `/healthz` is an alias of
  `/health` matching k8s convention. `/readyz` actively probes the
  configured upstream with a 1-second timeout and returns 503 when
  it is unreachable, so kubernetes can shed traffic without
  triggering a liveness restart.
- **`/health` body upgrade**. Now includes `version`,
  `uptime_seconds`, `pipeline_check_count`, and the last 8 hex of
  the audit-chain head HMAC (`audit_chain_head_hmac`) — enough for
  monitoring to distinguish "alive" from "alive and writing the
  expected configuration".
- **`Check.priority`** attribute. Sub-orders execution within a
  single `Stage`. Lower runs earlier; defaults to `0`. Use to enforce
  ordering dependencies between checks. Registration order remains
  authoritative on priority ties.
- **`RateLimitCheck.priority = 100`**. Schedules the rate-limit check
  late within ADMISSION so cheaper content-scanning checks
  (`RegexContent`, `PromptInjection`, classification) refuse a bad
  request *before* a token is consumed from the owner's bucket.
  Closes the "refused requests still cost quota" footgun.
- **`RateLimitCheck` hard-quota mode**. Pass `refill_per_second=0`
  for a never-refilling cap. The bucket drains once and never
  replenishes within the process — useful for daily / monthly
  quotas reset out-of-band. The error response carries
  `hard_quota=True` and `retry_after_seconds=None` so callers can
  distinguish a recoverable rate-limit from a hard cap.
- **`ServerConfig.strict_error_redaction`** (default `True`). 4xx
  refusal bodies are coarsened to
  `{"error": "refused", "correlation_id": "<entry_id>"}` so the
  public response no longer names the firing check, its rule, or
  the severity. Full detail still lands in the audit chain.
  `--strict-error-redaction` / `--no-strict-error-redaction` CLI
  flags; `signet serve --dev` flips the default to `False` for
  integration ergonomics.
- **`signet doctor` auto-detection**. When invoked inside a
  `signet init` workspace, `doctor` reads `SIGNET_UPSTREAM_URL`
  from `.env` / `.env.example` and defaults `--self` to
  `http://127.0.0.1:8443`. Mirrors the convenience that
  `serve --dev` already had.
- **`Owner.create(type=, id=)`** factory and
  **`KeyRing(keys=[...], active_id=...)`** / **`KeyRing(keys={...},
  active_id=...)`** constructor shapes. Backwards-compatible
  ergonomic aliases for the longer historical kwargs. The
  `Owner.human / Owner.agent / Owner.policy` classmethods remain the
  recommended path for typical use; `create` is the one-stop entry
  point for callers who want a single constructor.
- **`RequestContext.method`** field (default `"POST"`). Surfaced so
  checks that gate on HTTP verb don't have to read raw headers.
  Populated by the proxy from `request.method`.
- **`ToolSpec.as_metadata()`** helper. Projects a
  `ToolCallInspectorCheck` registry entry into the dict shape
  expected by `ToolCallContext.tool_metadata`, so consumers don't
  have to maintain two parallel registries.
- **`SandboxPreviewCheck(registry=...)`** parameter. When supplied,
  the sandbox plugin reads `dryrun_supported` directly from the
  shared `ToolSpec` registry rather than expecting
  `ToolCallContext.tool_metadata` to be populated by hand. The
  inspector's registry becomes the single source of truth.
- **Production deployment guide** at `docs/deploying.md`. mTLS /
  CSRF posture, multi-process worker rules, anchor-backend
  selection, HSM/KMS integration notes, probe wiring.

### Changed

- `RateLimitCheck` no longer rejects `refill_per_second=0`. The
  validator now requires `refill_per_second >= 0` and tells the
  caller about hard-quota mode in the error message.
- README's prompt-injection section calls out the
  `match_source: "decoded-base64"` audit field as the evidence
  surface for end-to-end obfuscation handling.
- `OwnerResolutionCheck` module docstring documents the
  `require_owner=True` ↔ `OwnerType.UNRESOLVED` flow with a
  4-line example, including the strict-redaction body shape.
- `LangchainSignetCallbackHandler` recognizes both the new strict
  refusal body (`error == "refused"`) and the legacy verbose body
  (`error.startswith("signet refused")`).

### Internal

- `Pipeline.__init__` sort key is now `(stage.ordinal, priority)`,
  not just `stage.ordinal`. Stable sort on registration order is
  preserved for any check that doesn't override `priority`.

## [0.1.4] — 2026-05-03

### Documentation accuracy pass

This is a doc-only release so the README on PyPI's project page
reflects what v0.1.3 actually shipped. No code changes.

- README "Honest scope" section rewritten. Removed stale "roadmap
  for v0.2" claims about ed25519 receipts, RFC 3161 anchoring,
  multi-process audit writers, and embeddings/completions —
  all shipped in v0.1.3. Restructured into "architectural
  boundaries" (things signet doesn't do because they belong
  elsewhere) + "When you need more than the OSS" (the legitimate
  Pro/Thornveil call for production-tuned LLM-judge calibration,
  behavioral fingerprinting, HSM integrations, compliance
  attestation, custom check development).
- README built-in-checks table updated to reflect the v0.1.3
  PromptInjection improvements (NFKC, confusables fold, multi-
  encoding decoders).
- `SECURITY.md` threat model updated: tamper-evidence now points
  at the actually-shipped `Rfc3161Anchor`; receipt symmetry now
  points at the actually-shipped `Ed25519ReceiptSigner`; multi-
  process writer warning now points at the actually-shipped
  `FileLockingJsonlBackend`. Stale "v0.2 supply-chain roadmap"
  removed.
- `docs/architecture.md` "two limits" section reframed as "two
  architectural choices" — both choices are now operator-config
  decisions, not future work.
- 7 new check pages: `loopback_trust`, `rate_limit`, `regex_content`,
  `prompt_injection`, `token_budget`, `scope_drift`,
  `continuing_consent`, `tool_call_inspector`. Each documents
  what the check does, configuration patterns, audit-row shapes,
  and known false-positive surface. The mkdocs nav now lists all
  10 built-in checks.

## [0.1.3] — 2026-05-03

### Added — Phase 1: bulletproof OSS

- **Asymmetric receipt signing (ed25519)** via
  `signet.server.receipt.Ed25519ReceiptSigner` and
  `signet keys generate-ed25519` CLI command. Verifiers hold only
  the public key and cannot forge. Optional dep
  `pip install signet-sign[ed25519]`.
- **External anchor backends** for tamper-proof audit chains.
  `signet.audit.anchor.AnchorBackend` Protocol + `NoopAnchor` (default,
  byte-compat) + `Rfc3161Anchor` (FreeTSA / any free public RFC 3161
  TSA, requires no extra deps). Anchor receipt embedded in entry
  metadata BEFORE the chain HMAC is computed, so the HMAC binds the
  receipt to the entry.
- **Multi-process safe audit writer** via
  `signet.audit.backend.FileLockingJsonlBackend` (fcntl on POSIX,
  msvcrt on Windows). Pair with `HmacChain(cache_prev=False)` to run
  uvicorn `--workers N>1` safely.
- **Endpoint coverage**: `/v1/embeddings` and `/v1/completions` are
  now gated through the full pipeline. `/v1/audio/*` and
  `/v1/images/*` remain explicit 404s with a roadmap note (their
  non-JSON request shapes need their own check protocols).
- **PromptInjection obfuscation hardening**: Unicode NFKC
  normalization, Cyrillic / Greek / Cherokee confusables fold,
  zero-width / bidi character stripping, "stretched" letter-spaced
  text collapse (`i g n o r e` → `ignore`), wider encoding decoders
  (URL-safe base64, base32, hex, ROT13). Module docstring documents
  the bypass surface still left open and points at production-tuned
  LLM-judge layer for the rest.
- **Auth integration recipes** at `docs/integrations/auth.md` —
  three concrete patterns (nginx + mTLS, FastAPI middleware + JWT,
  oauth2-proxy + OIDC) for putting real authentication in front of
  signet's owner-resolution gate.

### Added — Phase 2: production-grade ops

- **`/metrics` Prometheus endpoint** with counters:
  `signet_requests_total{path}`,
  `signet_pipeline_decisions_total{check, decision}`,
  `signet_audit_chain_appends_total`,
  `signet_audit_anchor_failures_total{backend}`, plus a
  `signet_uptime_seconds` gauge. No external dep — exposition
  format written manually.
- **CORS support** via `ServerConfig.cors_allowed_origins` (+
  methods / headers / credentials / preflight-cache fields). Skipped
  entirely when origins is empty (default), so non-browser
  deployments incur zero overhead.
- **Per-check timeout** via `Check.timeout_seconds`. Pipeline wraps
  each hook call in `asyncio.wait_for`; timeout fails closed (BLOCK
  with a clear reason). Bounds external dependencies (LLM-judge
  calls, sandbox runners) so a stuck dependency cannot halt the proxy.
- **Graceful shutdown**: lifespan exit waits up to
  `ServerConfig.shutdown_grace_seconds` (default 10s) for in-flight
  streaming responses to drain before tearing down the upstream
  client. Audit rows for abandoned streams still write via the
  generator's finally block.
- **`signet audit count`** / **`signet audit tail`** CLI
  subcommands. `audit count --by check|owner|decision|owner_type|stage`
  for incident-response counts; `audit tail -n 50 --filter
  decision=block` for log inspection. Both support `--json` for
  scripting.
- **`signet audit verify --json`** machine-readable output mode
  for CI cron consumers.
- **Redis-backed state stores**:
  `signet.server.redis_session_store.RedisSessionStore` and
  `signet.checks.redis_rate_limit_state.RedisRateLimitState` —
  drop-in replacements for the in-memory defaults when running
  multiple replicas. Optional dep
  `pip install signet-sign[redis]`.
- **`--log-format json`** flag on `signet serve` switches stdlib
  logging output to structlog's JSON renderer (one JSON object per
  line). Wire to Loki/Datadog/ELK without changing signet code.

### Documentation polish

- **Docs site nav** keeps Contributing / Security / Changelog
  inside the site (mkdocs `pymdownx.snippets` mirrors the canonical
  root files; GitHub keeps auto-discovering the originals). README
  gets explicit "📚 Documentation: jeranaias.github.io/signet" link
  with PyPI / docs / license / Python badges at the top.
- `CONTRIBUTING.md` internal links upgraded to absolute GitHub URLs
  so they resolve cleanly in both the repo browser and the included
  docs-site page.
- GitHub repo description corrected — `signet` is a proper noun, not
  preceded by an article.

### Tooling

- `pyproject.toml` extras: `[ed25519]`, `[redis]`,
  `[prometheus]`. `[all]` includes them all. `[dev]` pulls them
  for dev-environment coverage.
- `ruff` per-file-ignores for the deliberately-non-ASCII confusables
  table in `prompt_injection.py` + the obfuscation-attack tests.
- Cross-platform mypy fix: file-locking implementation selected at
  module import time via `sys.platform` narrowing — keeps mypy clean
  on both Linux and Windows.

### Tests

- 242 unit + adversarial green. mypy `--strict` clean. ruff lint
  clean. mkdocs `--strict` build clean.
- New tests: ed25519 sign/verify roundtrip + verify-only-cannot-sign +
  alg-downgrade rejection + PEM-roundtrip; anchor receipt binding
  to chain HMAC + failing-anchor-recorded-as-failure +
  require_anchor_success raises; FileLockingJsonlBackend basic +
  two-instance shared-file safety; PromptInjection obfuscation-
  busting (5 homoglyph variants + ROT13 + URL-safe base64);
  embeddings/completions endpoint round-trips; Redis adapters
  (sessions + rate-limit) end-to-end via fakeredis.

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

[Unreleased]: https://github.com/jeranaias/signet/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/jeranaias/signet/releases/tag/v0.1.4
[0.1.3]: https://github.com/jeranaias/signet/releases/tag/v0.1.3
[0.1.2]: https://github.com/jeranaias/signet/releases/tag/v0.1.2
[0.1.1]: https://github.com/jeranaias/signet/releases/tag/v0.1.1
[0.1.0]: https://github.com/jeranaias/signet/releases/tag/v0.1.0
