# RateLimitCheck

## What it does

Per-owner token-bucket rate limiting. Each resolved
[`Owner`](owner_resolution.md) gets its own bucket; tokens refill at a
configurable rate; requests beyond the bucket return `429 Too Many
Requests` with a `retry_after_seconds` hint.

Best for the common "be reasonable about throughput" case. For
strict cumulative-token quotas (e.g. "alice may use at most 1M
output tokens per day") use [`TokenBudgetCheck`](token_budget.md)
instead.

## Stage

`ADMISSION`.

## Configuration

```python
from signet.checks import RateLimitCheck

# 60 req/min sustained, burst up to 60
RateLimitCheck(capacity=60, refill_per_second=1.0)

# Strict: 1 req/sec, no burst tolerance
RateLimitCheck(capacity=1, refill_per_second=1.0)

# Multi-replica: pair with the Redis state store
import redis
from signet.checks.redis_rate_limit_state import RedisRateLimitState

state = RedisRateLimitState(client=redis.Redis(host="redis.internal", decode_responses=True))
RateLimitCheck(capacity=60, refill_per_second=1.0, state=state)
```

State backends:

- `InMemoryRateLimitState` (default): per-process LRU-bounded dict
  (default 50,000 owners). Lost on restart.
- `RedisRateLimitState` (`signet.checks.redis_rate_limit_state`):
  shared across replicas, survives restarts. Optional dep
  `pip install signet-sign[redis]`.

Custom backends: implement the `RateLimitState` protocol.

## Audit row example

When a request is throttled:

```json
{
  "check_name": "rate_limit",
  "decision": "block",
  "reason": "rate limit exceeded",
  "metadata": {
    "retry_after_seconds": 0.872,
    "capacity": 60,
    "refill_per_second": 1.0
  }
}
```

The proxy translates the BLOCK to HTTP 429 and includes the
`retry_after_seconds` value in the response body so SDK retry
helpers can wait the right amount.

## Owner-resolution coupling

`RateLimitCheck` skips requests whose owner is `unresolved` and
returns ALLOW — the throttle is a per-owner concept. Stack
[`OwnerResolutionCheck`](owner_resolution.md) earlier in the
pipeline so this check has an owner to bucket against.

## Multi-replica behavior

With `InMemoryRateLimitState`, each signet replica has an
independent view of the bucket — a 60 req/min cap with two replicas
allows 120 req/min in practice. Use `RedisRateLimitState` for
strict cross-replica enforcement, or accept the headroom and tune
`capacity` accordingly.
