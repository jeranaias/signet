"""RateLimitCheck — per-owner token-bucket throttling.

Each :class:`Owner` gets its own token bucket. Tokens refill at a steady
rate and are consumed one per request. When the bucket is empty, the
request is blocked with a ``Retry-After`` hint.

Token-bucket vs sliding-window:

* **Token bucket** (this implementation): cheap O(1) per request; allows
  short bursts up to the bucket capacity; smoothes long-running averages
  to the refill rate. Best fit for most agent-traffic shapes.
* Sliding window: stricter; better when fairness within a fixed
  time window matters more than burst tolerance. Implement as a plugin
  if you need it.

State is in-process by default. For multi-replica deployments, supply a
``state_backend`` that persists buckets across replicas (Redis, memcached,
etc.) — the protocol is documented on :class:`RateLimitState`.

Owners with type :attr:`OwnerType.UNRESOLVED` are deliberately *not*
counted; they should never reach this check (owner-resolution refuses
them at an earlier ADMISSION step). If they do, this check passes through
to surface the upstream bug rather than masking it with rate-limit
errors.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.owner import Owner, OwnerType
from signet.core.stage import Stage


@dataclass
class _Bucket:
    """A single owner's token-bucket state."""

    tokens: float
    last_refill_ts: float


class RateLimitState(Protocol):
    """Protocol for storing per-owner bucket state.

    The default in-process implementation is :class:`InMemoryRateLimitState`.
    Plug in a Redis-backed implementation for multi-replica deployments.
    """

    def get(self, owner_key: str) -> _Bucket | None: ...
    def set(self, owner_key: str, bucket: _Bucket) -> None: ...


class InMemoryRateLimitState:
    """Process-local bucket store. Fine for single-replica deployments."""

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}

    def get(self, owner_key: str) -> _Bucket | None:
        return self._buckets.get(owner_key)

    def set(self, owner_key: str, bucket: _Bucket) -> None:
        self._buckets[owner_key] = bucket


class RateLimitCheck(Check):
    """Per-owner token-bucket throttle.

    Args:
        capacity: Maximum tokens a bucket can hold (the burst allowance).
        refill_per_second: Steady-state allowed request rate. The bucket
            refills at this rate, capped at ``capacity``.
        state: Bucket-state backend. Defaults to
            :class:`InMemoryRateLimitState`.
    """

    name = "rate_limit"
    stage = Stage.ADMISSION

    def __init__(
        self,
        *,
        capacity: int = 60,
        refill_per_second: float = 1.0,
        state: RateLimitState | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        if refill_per_second <= 0:
            raise ValueError(f"refill_per_second must be > 0, got {refill_per_second}")

        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._state: RateLimitState = state if state is not None else InMemoryRateLimitState()

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        if ctx.owner.owner_type is OwnerType.UNRESOLVED:
            # Pass through — this should have been caught earlier.
            return CheckResult.allow()

        key = self._key_for(ctx.owner)
        now = time.monotonic()

        bucket = self._state.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.capacity), last_refill_ts=now)

        # Refill since last check
        elapsed = max(0.0, now - bucket.last_refill_ts)
        bucket.tokens = min(
            float(self.capacity),
            bucket.tokens + elapsed * self.refill_per_second,
        )
        bucket.last_refill_ts = now

        if bucket.tokens < 1.0:
            wait = (1.0 - bucket.tokens) / self.refill_per_second
            self._state.set(key, bucket)
            return CheckResult.block(
                "rate limit exceeded",
                retry_after_seconds=round(wait, 3),
                capacity=self.capacity,
                refill_per_second=self.refill_per_second,
            )

        bucket.tokens -= 1.0
        self._state.set(key, bucket)
        return CheckResult.allow(
            "rate limit ok",
            tokens_remaining=round(bucket.tokens, 3),
        )

    @staticmethod
    def _key_for(owner: Owner) -> str:
        """Stable bucket key per owner identity."""
        return f"{owner.owner_type.value}:{owner.owner_id}"
