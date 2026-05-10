"""RateLimitCheck -- per-owner token-bucket throttling.

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

Hard-quota mode: pass ``refill_per_second=0`` for a never-refilling cap.
The bucket starts at ``capacity``, drains as requests arrive, and never
replenishes for the lifetime of the process (or until the LRU evicts the
entry). Use for daily/monthly hard ceilings where you reset the state
out-of-band (e.g. by restarting the proxy at quota-window rollover, or
by clearing the Redis key behind a custom :class:`RateLimitState`).

Where this check sits in ADMISSION: ``priority=100`` schedules it last
within the stage so cheaper content checks (regex, prompt-injection,
classification) get to refuse a bad request before its token gets
consumed. Without this, a misbehaving caller drains its own quota on
requests that were always going to be blocked downstream.

State is in-process by default. For multi-replica deployments, supply a
``state_backend`` that persists buckets across replicas (Redis, memcached,
etc.) -- the protocol is documented on :class:`RateLimitState`.

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
    """Process-local bucket store with bounded LRU eviction.

    Without a bound, an attacker that rotates owner identities (each
    with a one-token bucket) inflates the store unboundedly. The LRU
    bound caps memory at ``max_owners`` entries; the least-recently
    touched bucket gets evicted on overflow. Default ceiling 50 000 is
    generous for legitimate fleets and cheap to keep in RAM.
    """

    def __init__(self, *, max_owners: int = 50_000) -> None:
        if max_owners < 1:
            raise ValueError(f"max_owners must be >= 1, got {max_owners}")
        # OrderedDict gives O(1) LRU promotion via move_to_end + popitem.
        from collections import OrderedDict

        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._max = max_owners

    def get(self, owner_key: str) -> _Bucket | None:
        bucket = self._buckets.get(owner_key)
        if bucket is not None:
            self._buckets.move_to_end(owner_key)
        return bucket

    def set(self, owner_key: str, bucket: _Bucket) -> None:
        self._buckets[owner_key] = bucket
        self._buckets.move_to_end(owner_key)
        while len(self._buckets) > self._max:
            self._buckets.popitem(last=False)


class RateLimitCheck(Check):
    """Per-owner token-bucket throttle.

    Args:
        capacity: Maximum tokens a bucket can hold (the burst allowance).
        refill_per_second: Steady-state allowed request rate. The bucket
            refills at this rate, capped at ``capacity``. Pass ``0`` for
            hard-quota mode (no refill, just cap) -- the bucket drains
            once and never replenishes until external state reset.
        state: Bucket-state backend. Defaults to
            :class:`InMemoryRateLimitState`.
    """

    name = "rate_limit"
    stage = Stage.ADMISSION
    # Schedule late within ADMISSION so cheaper content checks
    # (regex, prompt-injection, classification) refuse bad requests
    # before this check consumes a token from the owner's bucket.
    priority = 100

    def __init__(
        self,
        *,
        capacity: int = 60,
        refill_per_second: float = 1.0,
        state: RateLimitState | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        if refill_per_second < 0:
            raise ValueError(
                f"refill_per_second must be >= 0, got {refill_per_second}. "
                "Pass 0 for hard-quota mode (no refill, never replenishes); "
                "pass a positive float for the steady-state request rate."
            )

        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._state: RateLimitState = state if state is not None else InMemoryRateLimitState()

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        if ctx.owner.owner_type is OwnerType.UNRESOLVED:
            # Pass through -- this should have been caught earlier.
            return CheckResult.allow()

        key = self._key_for(ctx.owner)
        now = time.monotonic()

        # Fail-closed posture against backend errors (Redis down, network
        # partition, etc.). The docstring's ``fail-closed`` promise is
        # only true if a flaky state backend produces a ``BLOCK``
        # decision rather than letting the exception become a 500 at the
        # proxy. We catch broadly because backend implementations may
        # raise anything from ``ConnectionError`` to provider-specific
        # subclasses; the audit metadata captures the type for triage.
        try:
            bucket = self._state.get(key)
        except Exception as exc:
            return CheckResult.block(
                "rate-limit backend unavailable; failing closed",
                backend_error=type(exc).__name__,
                backend_message=str(exc),
            )
        if bucket is None:
            bucket = _Bucket(tokens=float(self.capacity), last_refill_ts=now)

        # Refill since last check. With refill_per_second=0 (hard-quota
        # mode), this is a no-op -- elapsed * 0 is 0, so the bucket only
        # ever drains.
        elapsed = max(0.0, now - bucket.last_refill_ts)
        bucket.tokens = min(
            float(self.capacity),
            bucket.tokens + elapsed * self.refill_per_second,
        )
        bucket.last_refill_ts = now

        if bucket.tokens < 1.0:
            # Hard-quota mode never recovers within this process; signal
            # that to callers so they don't poll uselessly. Keep the
            # field in the response so the shape stays stable.
            if self.refill_per_second == 0:
                wait_meta: float | None = None
            else:
                wait_meta = round((1.0 - bucket.tokens) / self.refill_per_second, 3)
            try:
                self._state.set(key, bucket)
            except Exception as exc:
                return CheckResult.block(
                    "rate-limit backend unavailable; failing closed",
                    backend_error=type(exc).__name__,
                    backend_message=str(exc),
                )
            return CheckResult.block(
                "rate limit exceeded",
                retry_after_seconds=wait_meta,
                capacity=self.capacity,
                refill_per_second=self.refill_per_second,
                hard_quota=self.refill_per_second == 0,
            )

        bucket.tokens -= 1.0
        try:
            self._state.set(key, bucket)
        except Exception as exc:
            return CheckResult.block(
                "rate-limit backend unavailable; failing closed",
                backend_error=type(exc).__name__,
                backend_message=str(exc),
            )
        return CheckResult.allow(
            "rate limit ok",
            tokens_remaining=round(bucket.tokens, 3),
        )

    @staticmethod
    def _key_for(owner: Owner) -> str:
        """Stable bucket key per owner identity."""
        return f"{owner.owner_type.value}:{owner.owner_id}"
