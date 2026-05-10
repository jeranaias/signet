# Public bug-hunt log

This file is the public record of every bug-hunt cycle signet has been through. It exists to make the project credible: the bugs we shipped, the bugs we missed, the bugs we found, and the bugs we fixed are all here in chronological order.

The point of recording this isn't transparency for its own sake. It's that an LLM safety gate that hides its failure modes is one you can't trust. The discipline this project commits to: every published version that fails a stated promise gets that failure documented here, and every hunt cycle that surfaces new bugs adds them.

## How to read this file

- **Cycle**: a hunt + polish + verify round, terminated by a release tag.
- **Hunters**: who or what surfaced the findings (Claude Code subagents in domain-isolated parallel sweeps to date).
- **Findings**: P0 (broken contract / leaks data / silently fails) → P1 (wrong output) → P2 (ergonomic) → P3 (doc gap).
- **Resolved**: how each finding was closed.

---

## Cycle 1 — v0.1.5 evaluation pass (2026-05-06)

**Hunters**: external evaluation pass by SSgt Jesse Morgan against v0.1.4 release artifact.

**Surface area examined**: 13-item curated polish list. Targeted at operator-day-one friction points.

**Findings**: 13 (P0: 3, P1: 6, P2: 4)

Key headlines: rate-limit consumed tokens for downstream-blocked requests (B1 footgun); error responses leaked check names and rule labels by default; no `/healthz` / `/readyz` aliases; constructor naming drift; no `--shadow` mode for non-enforcing pilots.

**Resolved in**: v0.1.5 release on 2026-05-06.

---

## Cycle 2 — v0.1.6 architectural-stretch (2026-05-06 to 2026-05-07)

**Hunters**: built six P3 architectural features (plugins, audit compaction, streaming abort, audit report, WebSocket realtime, escalation surface); the streaming-harness work surfaced 5 bugs in code that was happily shipping at v0.1.5.

**The five A3 bugs**:
1. Abort-frame discriminator was `signet_aborted` not `signet_abort` (wire-spec mismatch)
2. Abort frame missed `correlation_id` and `stage` (audit chain blind spot)
3. No strict-redaction coarsening on the abort frame (reason leaked)
4. Audit row for inspection-block didn't capture partial chunk state
5. Upstream protocol violation / mid-stream 5xx emitted nothing (hung connections)

All five fixed within the v0.1.6 sprint window before final tag.

**Lesson recorded**: building the test harness paid for itself in the same sprint. The harness is a permanent fixture, not a one-time check.

**Resolved in**: v0.1.6 release on 2026-05-07.

---

## Cycle 3 — Claude Code test post (2026-05-07)

**Hunter**: ad-hoc fresh-install test against `signet-sign==0.1.6` from PyPI; structured as material for an "I gave Claude Code Signet to test" public post.

**Findings**: 1 P0 + 4 minor.

- **P0**: `signet doctor --probe-injection` against the live proxy reported 3 of 9 corpus entries leaked through (base64, base32, hex encoded "ignore previous instructions"). The README explicitly claimed these decoders worked since v0.1.3. The tool's own probe corpus, shipped in v0.1.6 as N1, caught the gap. That's the system working as designed — the hunter that ships with the release found the hunt-worthy bug in the release itself.
- **Minor**: em-dash encoding on Windows cp1252 (`�` instead of `—`); `signet lint` success message hardcoded `v0.1.5`; `audit report --no-anonymize` kept the "(anonymized)" header; "1 blocks" pluralization; scaffold `LoopbackTrustCheck` quietly bypasses owner resolution on 127.0.0.1.

**Resolved in**: cycle 4 (v0.1.7 polish release).

---

## Cycle 4 — v0.1.7 full bug-hunt (2026-05-09)

**Hunters**: five Claude Code subagents in parallel against `signet-sign==0.1.6` from PyPI:
- Audit subsystem
- Server core + ergonomics
- Streaming + WebSocket realtime
- Pipeline checks + concurrency + adversarial inputs
- CLI + plugins + receipts

**Total findings**: ~98 distinct issues.

**Severity distribution**:
- P0 / HIGH: 17
- P1 / MED: ~25
- P2 / LOW: ~45
- P3 / doc: ~10

**Headline findings**:

| # | Where | What was broken |
|---|---|---|
| S1 | streaming + scope_drift | Classification-leak via accumulated_text_cap; pad with 1 MiB of benign then leak `(S//NF)`, INSPECTION misses it |
| S2 | streaming/abort | Strict mode coarsens `upstream_protocol_violation` to `refused`, breaking SDK retry contract |
| S3 | streaming/abort | Non-httpx upstream exceptions bypass abort frame, audit chain records ALLOW |
| A1 | verify/archives | `verify --including-archives` crashes on corrupted gzip body (traceback instead of structured break) |
| A2 | compaction | Stacked compactions break verify silently |
| A3 | verifier | `audit verify` crashes on any malformed JSONL line |
| H1 | server/admit | `_handle_chat` 500s on body=`[]`/`null`/`123`; no audit row written |
| H2 | server/upstream | Non-JSON / 302 upstream responses lose `X-Signet-Upstream*` attribution |
| H4 | config | `SIGNET_SHADOW=1` doesn't enable shadow (only `"true"`); CHANGELOG markets `=1` |
| C4.1 | RegexContent | ReDoS hangs the asyncio loop; `Pipeline.timeout_seconds` can't rescue (sync C call) |
| C8.1 | TokenBudget | Pre-flight estimate not reserved; burst race opens the cap |
| C3.1 | RateLimit | Backend exception raises instead of fail-closing |
| C6 | PromptInjection | base64 / base32 / hex decoders silently miss real payloads |
| C1.1 | OwnerResolution | CRLF injection in `X-Commit-Owner` lands in audit chain |
| C1 | doctor | `signet doctor --self <down>` exits 0 (CI gate silently passes a dead proxy) |
| C2 | init | `signet init` overwrites `client_example.py` and `.env.example` silently |
| P1 | plugins/discovery | Duplicate plugin names silently shadow on resolve |

**Resolution**: v0.1.7 lands every P0/HIGH plus ~25 P1/MED. 705 unit + integration tests gate every found bug.

**Three RC tags**: rc1 (P0/HIGH bugs) → rc2 (P1/P2 polish) → rc3 (docs sweep) → final.

**Marketing material**: `growth/v017_polish_release.md` ("v0.1.6 had 98 bugs. v0.1.7 has tests for all of them.")

---

## Cycle 5 — v0.1.7 confidence hunt (2026-05-10)

**Hunters**: same five subagents, re-run against `signet-sign==0.1.7` from PyPI. The point: don't trust the polish release until the hunt finds nothing actually-broken.

**Total findings**: 14 (P0: 3, P1: 5, P2: 4, P3: 2). Probe corpus 9/9 (was 6/9 in v0.1.6).

**Critical findings still open at v0.1.7 ship**:

1. **S1 still P0**: the v0.1.7 commit message claimed scope_drift would scan the current chunk parameter in addition to the accumulated buffer. It doesn't. `scope_drift.py:164` accepts `chunk` but never uses it. Same attack primitive as v0.1.6.
2. **N1 [HIGH]**: ROT13 fast-path English-prefix bypass. The new "skip ROT13 if natural English" check samples only `text[:4096]`. Prepend 4 KB of stop-words, place ROT13 attack in the tail, and the decoder skips. **Regression introduced by v0.1.7's C6.7 fix.**
3. **N2 [HIGH]**: PromptInjection truncation-tail bypass. `scan_max_chars=512KB` cap means an attacker can place injection past the cap. Returns ALLOW with `scan_truncated=True` metadata, but no built-in policy promotes that flag to BLOCK.
4. **NF1 [HIGH]**: Malformed-body 400 writes NO audit row. H1's fix landed the response shape but not the audit row. The 400-generator is back to silent on the chain.
5. **V2 [HIGH]**: `HmacChain.append` reads chain head OUTSIDE the cross-process lock. A7's lock landed for the compactor but not the appender path. On Windows, 30+ concurrent appenders trigger PermissionError-driven silent data loss.

**Still-broken charter promises**:
- A9: anonymize slug still 8 hex chars (CHANGELOG says 16)
- A13/F2: `audit verify --json` missing `signet_version` + `verified_at`
- F1: `audit compact --force` raises bare ValueError (CLI traceback leak)
- F3: `signet doctor --probe-injection` against the `signet init` scaffold reports 9/9 LEAKED because the scaffold lacks PromptInjectionCheck

**Net for v0.1.7**: a major step up from v0.1.6 (~90% of P0/HIGH genuinely closed; probe corpus moved from 6/9 to 9/9), but **the headline classification-leak primitive (S1) is unfixed and Phase 1's prompt-injection improvements introduced two new HIGH bypasses**.

**Resolution**: v0.1.8 patch release (in progress).

---

## Cycle 6 — v0.1.8 the-world-needs-this release (2026-05-10, ongoing)

**Goal**: ship the version that actually delivers on signet's promises. Every P0 from cycle 5 closed. Every CHANGELOG promise from v0.1.7 verified true. New surfaces added that close adoption gaps:

- `signet bench`: prove the per-request overhead claim with measurable output
- Public bug-hunt log (this file) as the credibility artifact
- Docker-compose + GitHub Action example for one-command production wiring
- README "why use this" section refreshed

**Findings closed (in progress)**: …

This section will be updated as v0.1.8 lands.
