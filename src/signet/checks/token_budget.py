"""TokenBudgetCheck -- per-owner output token quotas.

Distinct from :class:`signet.checks.rate_limit.RateLimitCheck` (request
count) -- this caps the *output volume* an owner can consume per window.
Useful where each request is cheap to send but expensive to fulfill,
e.g. long-context completions or video generation.

Two-mode operation:

* **ADMISSION-stage check**: at request time, we don't yet know the
  output size. We can only check what's been used so far in the window
  vs the cap, plus the *requested* ``max_tokens`` parameter as a
  pessimistic estimate. v0.1.7 reserves the estimate against the
  bucket -- concurrent admissions see each other's reservations and
  the burst-race window closes. Refuse if (used + reserved + requested)
  exceeds cap.
* **RECORD-stage check**: after the response completes, we refund the
  at-admission reservation, then add the actual ``completion_tokens``
  from upstream usage so the next ADMISSION call sees accurate state.

The check class is registered under ADMISSION and runs at both hooks
internally -- :meth:`pre_request` does the budget check;
:meth:`post_complete` reconciles reservation + actual usage.

Window granularity is configurable: per-minute, per-hour, per-day.
Defaults to per-day matching how most LLM cost budgets are framed.

The per-owner ``_windows`` map is bounded by ``max_owners`` (LRU
eviction). Without that bound, an attacker rotating identities would
inflate memory unboundedly -- same fix surface as
:class:`signet.checks.rate_limit.InMemoryRateLimitState`.
"""

from __future__ import annotations

import enum
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner, OwnerType
from signet.core.stage import Stage

# Per-request scratch key used to thread the at-admission reservation
# through to the post-complete refund. Namespaced with a leading
# underscore so it doesn't collide with caller-owned scratch entries.
_SCRATCH_RESERVED_KEY = "_token_budget_reserved"

# Default LRU ceiling for the per-owner ``_windows`` map. Mirrors
# :class:`signet.checks.rate_limit.InMemoryRateLimitState`. An attacker
# that rotates owner identities (each producing a fresh ``Owner.human``)
# would otherwise inflate the store unboundedly.
_DEFAULT_MAX_OWNERS = 50_000


class WindowSize(enum.IntEnum):
    """Window granularity in seconds."""

    MINUTE = 60
    HOUR = 3600
    DAY = 86400


@dataclass
class _Window:
    """Per-owner token-usage window.

    Splits committed usage (``used``) from outstanding admissions
    (``reserved``) so the admission gate can refuse before
    ``post_complete`` fires. Without the split, N concurrent admissions
    all see ``used=0`` and pass; the cap is unenforced under burst load.
    """

    used: int
    window_start_ts: float
    reserved: int = field(default=0)


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
        max_owners: LRU bound on the per-owner window map. Defaults to
            50 000 (matching the rate-limit store). Set to ``1`` for
            tests that want to force eviction on every owner change.
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
        max_owners: int = _DEFAULT_MAX_OWNERS,
    ) -> None:
        if cap < 1:
            raise ValueError(f"cap must be >= 1, got {cap}")
        if request_estimate_default < 0:
            raise ValueError(
                f"request_estimate_default must be >= 0, got {request_estimate_default}"
            )
        if max_owners < 1:
            raise ValueError(f"max_owners must be >= 1, got {max_owners}")

        self.cap = cap
        self.window = window
        self.request_estimate_field = request_estimate_field
        self.request_estimate_default = request_estimate_default
        self.max_owners = max_owners
        # OrderedDict gives O(1) LRU promotion via move_to_end + popitem.
        # An unbounded plain dict would let an attacker rotating owner
        # identities inflate the store indefinitely.
        self._windows: OrderedDict[str, _Window] = OrderedDict()

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        if ctx.owner.owner_type is OwnerType.UNRESOLVED:
            return CheckResult.allow()

        # C8.3 (v0.1.7): a negative ``max_tokens`` used to silently fall
        # back to ``request_estimate_default``. That hides operator
        # mistakes (off-by-one signs, env-var typos) until the budget
        # actually trips. Refuse at admission with a clear reason so
        # the caller learns immediately. We only check the configured
        # request_estimate_field (caller-controlled name); other
        # numeric fields are not in scope.
        v = ctx.body.get(self.request_estimate_field)
        if isinstance(v, int) and v < 0:
            return CheckResult.block(
                f"{self.request_estimate_field} must be non-negative, got {v}",
                request_estimate_field=self.request_estimate_field,
                received_value=v,
            )

        key = self._key_for(ctx.owner)
        window = self._current_window(key)
        estimate = self._request_estimate(ctx)

        # Reserve at admission so concurrent requests see each other's
        # in-flight estimates. Refund happens in :meth:`post_complete`.
        # ``used + reserved`` is the high-water mark the gate enforces.
        if window.used + window.reserved + estimate > self.cap:
            return CheckResult.block(
                f"token budget exceeded: would use "
                f"{window.used + window.reserved + estimate} "
                f"of {self.cap} per {self.window.name.lower()}",
                budget_used=window.used,
                budget_reserved=window.reserved,
                budget_cap=self.cap,
                request_estimate=estimate,
                window=self.window.name.lower(),
            )

        window.reserved += estimate
        # Track the reservation on per-request scratch so post_complete
        # refunds exactly what was reserved -- not whatever the request
        # body claims at completion time (the caller may not see the
        # request body again, and concurrent estimates would otherwise
        # drift the counter). We also keep the legacy
        # ``token_budget.estimated`` key for backwards compatibility.
        ctx.scratch[_SCRATCH_RESERVED_KEY] = estimate
        ctx.scratch["token_budget.estimated"] = estimate
        return CheckResult.allow(
            f"budget ok: {window.used}/{self.cap} used, "
            f"{window.reserved} reserved, +{estimate} estimated",
            budget_used=window.used,
            budget_reserved=window.reserved,
            budget_cap=self.cap,
            request_estimate=estimate,
        )

    async def post_complete(self, ctx: ResponseContext) -> CheckResult:
        """Refund the at-admission reservation, then add actual usage."""
        if ctx.request.owner.owner_type is OwnerType.UNRESOLVED:
            return CheckResult.allow()

        key = self._key_for(ctx.request.owner)
        window = self._current_window(key)

        # Refund whatever this request reserved at admission. If we
        # never reserved (e.g. the request was blocked downstream
        # before this hook ran, or the scratch entry was rotated away
        # by a window rollover), the refund is zero -- never negative,
        # never speculative.
        reserved = ctx.request.scratch.pop(_SCRATCH_RESERVED_KEY, 0)
        if isinstance(reserved, int) and reserved > 0:
            window.reserved = max(0, window.reserved - reserved)

        actual = ctx.usage.get("completion_tokens", 0)
        if actual > 0:
            window.used += actual
        self._windows[key] = window
        # Re-promote in the LRU on touch.
        self._windows.move_to_end(key)
        if actual <= 0:
            return CheckResult.allow(
                "no usage reported by upstream",
                budget_used=window.used,
                budget_reserved=window.reserved,
                budget_cap=self.cap,
            )
        return CheckResult.allow(
            f"budget updated: +{actual} tokens",
            budget_used=window.used,
            budget_reserved=window.reserved,
            budget_cap=self.cap,
        )

    def _current_window(self, key: str) -> _Window:
        """Return the active window, rolling over if expired.

        Also enforces the ``max_owners`` LRU bound -- the least-recently
        touched window is evicted on overflow, matching the semantics
        of :class:`signet.checks.rate_limit.InMemoryRateLimitState`.
        """
        now = time.time()
        existing = self._windows.get(key)
        if existing is None or (now - existing.window_start_ts) >= self.window.value:
            existing = _Window(used=0, window_start_ts=now)
        self._windows[key] = existing
        self._windows.move_to_end(key)
        while len(self._windows) > self.max_owners:
            self._windows.popitem(last=False)
        return existing

    def _request_estimate(self, ctx: RequestContext) -> int:
        """Best-effort estimate of this request's output token count.

        ``max_tokens=0`` and missing values fall back to a positive
        floor so the cap can't be bypassed by claiming "I'll use zero
        tokens" -- even a refused or empty completion costs the upstream
        a non-zero pre-fill.

        Negative values are refused at :meth:`pre_request` before we
        ever get here (C8.3), so the negative branch in this method is
        unreachable in production. It remains a defensive fallback for
        callers that bypass ``pre_request``.
        """
        v = ctx.body.get(self.request_estimate_field)
        # Floor for the missing / zero / negative cases. Clamps to at
        # least 1 (never zero) and to a sensible fraction of the
        # configured default so a misconfigured caller can't sneak
        # past with a string of ``max_tokens=0`` requests.
        floor = max(1, self.request_estimate_default // 100)
        if isinstance(v, int) and v > 0:
            return v
        if isinstance(v, int) and v == 0:
            # A request that asks for zero output still consumes input
            # tokens upstream; refuse the "no estimate at all" bypass.
            return floor
        # Missing or non-int: use the configured default, clamped to
        # at least the floor. (Negative ints are filtered upstream.)
        return max(floor, self.request_estimate_default)

    @staticmethod
    def _key_for(owner: Owner) -> str:
        return f"{owner.owner_type.value}:{owner.owner_id}"
