"""Production-grade signet pipeline for the docker-compose example.

Loaded by `signet serve --config /app/pipeline.py`. Edit this file in
place when you want different policy. The container will reload it on
next start.

The shape mirrors the recommended production layout in
docs/deploying.md:

    ADMISSION:    OwnerResolution (require_owner=True)
                  LoopbackTrust (auto-resolve same-host probes)
                  RateLimit
                  ClassificationGate
                  PromptInjection
    INSPECTION:   ScopeDrift
    COMMITMENT:   ToolCallInspector (empty registry == deny-by-default)

Notes:
  - The tool registry is intentionally empty. Add `ToolSpec(...)` entries
    when you turn on tool use; everything else is refused.
  - RateLimit defaults are tuned for a single-tenant dev cluster
    (60 req/min/owner). Re-tune for your traffic.
  - ScopeDriftCheck enforces token-count and classification drift on
    streamed output. Length drift requires the caller to set max_tokens
    on every request -- see docs/checks/scope_drift.md.
"""

from __future__ import annotations

from signet.checks import (
    ClassificationGateCheck,
    LoopbackTrustCheck,
    OwnerResolutionCheck,
    PromptInjectionCheck,
    RateLimitCheck,
    RiskTier,
    ScopeDriftCheck,
    ToolCallInspectorCheck,
)
from signet.core.pipeline import Pipeline


pipeline = Pipeline(
    checks=[
        # --- ADMISSION ----------------------------------------------------
        # Resolve loopback / same-host probes (k8s readiness, prometheus)
        # to a synthetic owner so health checks don't have to forge
        # X-Commit-Owner. Order matters: this must run before
        # OwnerResolutionCheck so the loopback resolver gets first crack.
        LoopbackTrustCheck(),
        # Refuse anything without a resolvable commit owner. This is the
        # load-bearing check; never relax it in production.
        OwnerResolutionCheck(require_owner=True),
        # Per-owner token bucket. 60 requests/minute steady-state, with a
        # burst of 60. Swap for RedisRateLimitState when running multi-
        # worker -- see docs/deploying.md "Rate limiting under multi-
        # process uvicorn".
        RateLimitCheck(capacity=60, refill_per_second=1.0),
        # 5-level classification ladder. Default config refuses cross-
        # ladder requests (e.g., SECRET caller asking for TS-tagged
        # content). Pair with ScopeDriftCheck below.
        ClassificationGateCheck(),
        # Pattern + heuristic prompt-injection scan on input. Refusals
        # are surfaced via correlation_id only (strict redaction); the
        # firing rule lives in the audit row.
        PromptInjectionCheck(),
        # --- INSPECTION ---------------------------------------------------
        # Watches the streamed output and aborts when it drifts past the
        # originally-approved scope (token count, classification markers).
        ScopeDriftCheck(),
        # --- COMMITMENT ---------------------------------------------------
        # Empty registry == deny every proposed tool call. Add entries
        # like:
        #     "list_files": ToolSpec(risk_tier=RiskTier.LOW),
        #     "send_email": ToolSpec(
        #         risk_tier=RiskTier.HIGH,
        #         irreversible=True,
        #         dryrun_supported=False,
        #     ),
        # before turning on tool use. `allow_critical=False` keeps
        # CRITICAL-tier tools refused even when explicitly registered.
        ToolCallInspectorCheck(
            registry={},
            max_allowed_tier=RiskTier.HIGH,
            allow_critical=False,
        ),
    ]
)
