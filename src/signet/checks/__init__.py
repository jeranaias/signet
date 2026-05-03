"""Built-in checks shipped with signet.

A check is one policy-evaluation step. The ten built-in checks cover the
most common controls; anything else is a plugin (see :mod:`signet.plugins`
for the discovery interface).

By stage:

ADMISSION
    * :class:`OwnerResolutionCheck` — refuse if no resolvable commit owner
    * :class:`LoopbackTrustCheck` — auto-resolve owner for trusted internal IPs
    * :class:`ClassificationGateCheck` — 5-level architectural enforcement
    * :class:`RateLimitCheck` — per-owner token-bucket
    * :class:`TokenBudgetCheck` — per-owner per-window output token quota
    * :class:`PromptInjectionCheck` — pattern + heuristic scan on input
    * :class:`RegexContentCheck` (input mode) — block/redact patterns in request

INSPECTION
    * :class:`RegexContentCheck` (output mode) — same patterns, output side
    * :class:`ContinuingConsentCheck` — re-evaluate owner authority mid-stream
    * :class:`ScopeDriftCheck` — abort when output exceeds the originally-approved scope

COMMITMENT
    * :class:`ToolCallInspectorCheck` — risk-tier gating + tool allowlist

These compose. A typical production pipeline runs all ADMISSION checks,
then both INSPECTION checks during streaming, then the COMMITMENT check
on each tool call. RECORD-stage checks are usually plugins (drift
detection, behavioral baselines).
"""

from __future__ import annotations

__all__: list[str] = []
