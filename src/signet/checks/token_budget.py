"""TokenBudgetCheck — per-owner output token quotas.

Distinct from :class:`signet.checks.rate_limit.RateLimitCheck` (request
count) — this caps the *output volume* an owner can consume per window.
Useful where each request is cheap to send but expensive to fulfill,
e.g. long-context completions or video generation.

Two-mode operation:

* **ADMISSION-stage check**: at request time, we don't yet know the
  output size. We can only check what's been used so far in the window
  vs the cap, plus the *requested* ``max_tokens`` parameter as a
  pessimistic estimate. Refuse if (used + requested) > cap.
* **RECORD-stage check**: after the response completes, we know the
  actual ``completion_tokens`` from upstream usage. Add that to the
  window's used counter so the next ADMISSION call sees accurate state.

The check class is registered under ADMISSION and runs at both hooks
internally — :meth:`pre_request` does the budget check;
:meth:`post_complete` updates the running total.

Window granularity is configurable: per-minute, per-hour, per-day.
Defaults to per-day matching how most LLM cost budgets are framed.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner, OwnerType
from signet.core.stage import Stage


class WindowSize(enum.IntEnum):
    """Window granularity in seconds."""

    MINUTE = 60
    HOUR = 3600
    DAY = 86400


@dataclass
class _Window:
    """Per-owner token-usage window."""

    used: int
    window_start_ts: float


class TokenBudgetCheck(Check):
    """Cap output tokens per owner per window.

    Args:
        cap: Maximum output tokens allowed per window.
        window: Window granularity. Defaults to per-day.
        request_estimate_field: Name of the request body field carrying
            the per-request output cap. Defaults to ``"max_tokens"``,
            matching OpenAI shape. If absent, a fallback estimate of
            ``request_estimate_default`` is used.
        request_estimate_default: Fallback estimate when the request
            doesn't declare ``max_tokens``. Defaults to 1024.
    """

    name = "token_budget"
    stage = Stage.ADMISSION

    def __init__(
        self,
        *,
        cap: int,
        window: WindowSize = WindowSize.DAY,
        request_estimate_field: str = "max_tokens",
        request_estimate_default: int = 1024,
    ) -> None:
        if cap < 1:
            raise ValueError(f"cap must be >= 1, got {cap}")
        if request_estimate_default < 0:
            raise ValueError(
                f"request_estimate_default must be >= 0, got {request_estimate_default}"
            )

        self.cap = cap
        self.window = window
        self.request_estimate_field = request_estimate_field
        self.request_estimate_default = request_estimate_default
        self._windows: dict[str, _Window] = {}

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        if ctx.owner.owner_type is OwnerType.UNRESOLVED:
            return CheckResult.allow()

        key = self._key_for(ctx.owner)
        window = self._current_window(key)
        estimate = self._request_estimate(ctx)

        if window.used + estimate > self.cap:
            return CheckResult.block(
                f"token budget exceeded: would use {window.used + estimate} "
                f"of {self.cap} per {self.window.name.lower()}",
                budget_used=window.used,
                budget_cap=self.cap,
                request_estimate=estimate,
                window=self.window.name.lower(),
            )

        # Stash the estimate so post_complete knows how to reconcile.
        ctx.scratch["token_budget.estimated"] = estimate
        return CheckResult.allow(
            f"budget ok: {window.used}/{self.cap} used, +{estimate} estimated",
            budget_used=window.used,
            budget_cap=self.cap,
            request_estimate=estimate,
        )

    async def post_complete(self, ctx: ResponseContext) -> CheckResult:
        """Update the window's used counter from actual upstream usage."""
        if ctx.request.owner.owner_type is OwnerType.UNRESOLVED:
            return CheckResult.allow()

        actual = ctx.usage.get("completion_tokens", 0)
        if actual <= 0:
            return CheckResult.allow("no usage reported by upstream")

        key = self._key_for(ctx.request.owner)
        window = self._current_window(key)
        window.used += actual
        self._windows[key] = window
        return CheckResult.allow(
            f"budget updated: +{actual} tokens",
            budget_used=window.used,
            budget_cap=self.cap,
        )

    def _current_window(self, key: str) -> _Window:
        """Return the active window, rolling over if expired."""
        now = time.time()
        existing = self._windows.get(key)
        if existing is None or (now - existing.window_start_ts) >= self.window.value:
            existing = _Window(used=0, window_start_ts=now)
            self._windows[key] = existing
        return existing

    def _request_estimate(self, ctx: RequestContext) -> int:
        v = ctx.body.get(self.request_estimate_field)
        if isinstance(v, int) and v >= 0:
            return v
        return self.request_estimate_default

    @staticmethod
    def _key_for(owner: Owner) -> str:
        return f"{owner.owner_type.value}:{owner.owner_id}"
