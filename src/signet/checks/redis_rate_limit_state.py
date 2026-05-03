"""Redis-backed RateLimitState — multi-replica per-owner rate limiting.

Drop-in replacement for :class:`signet.checks.rate_limit.InMemoryRateLimitState`
when you run multiple signet replicas and need rate-limit state to be
consistent across them.

Requires ``pip install signet-sign[redis]``.

Usage::

    import redis
    from signet.checks import RateLimitCheck
    from signet.checks.redis_rate_limit_state import RedisRateLimitState

    state = RedisRateLimitState(
        client=redis.Redis(host="redis.internal", decode_responses=True),
        prefix="signet:ratelimit:",
        ttl_seconds=86400,
    )
    pipeline = Pipeline(checks=[
        RateLimitCheck(capacity=60, refill_per_second=1.0, state=state),
        # ...
    ])

The bucket is stored as a Redis hash; updates are not atomic across
multiple workers, so concurrent burst rates may briefly exceed the
configured rate. For strict compliance with the configured rate
under high concurrency, use a Lua script (see Redis docs for an
atomic token-bucket). The OSS reference is correct for typical
agent-traffic shapes; production-grade strict limiters are a
common engagement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from signet.checks.rate_limit import _Bucket

if TYPE_CHECKING:
    import redis


class RedisRateLimitState:
    """Bucket store backed by a Redis client.

    Stores each owner's bucket as a Redis hash at
    ``{prefix}{owner_key}`` with fields ``tokens`` and ``last_refill_ts``.

    Args:
        client: A configured ``redis.Redis`` instance with
            ``decode_responses=True``.
        prefix: Key prefix for all rate-limit entries.
        ttl_seconds: TTL applied to each bucket on every write. Owners
            inactive longer than this are evicted automatically. Default
            24 hours; tune to match your owner-activity patterns.
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str = "signet:ratelimit:",
        ttl_seconds: int = 86400,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._ttl = ttl_seconds

    def _key(self, owner_key: str) -> str:
        return f"{self._prefix}{owner_key}"

    def get(self, owner_key: str) -> _Bucket | None:
        # The redis-py client is sync when constructed via ``redis.Redis``;
        # cast tells mypy the result is a dict, not an Awaitable.
        from typing import cast

        data: dict[str, str] = cast("dict[str, str]", self._client.hgetall(self._key(owner_key)))
        if not data:
            return None
        try:
            return _Bucket(
                tokens=float(data.get("tokens", 0)),
                last_refill_ts=float(data.get("last_refill_ts", 0)),
            )
        except (TypeError, ValueError):
            return None

    def set(self, owner_key: str, bucket: _Bucket) -> None:
        key = self._key(owner_key)
        self._client.hset(
            key,
            mapping={
                "tokens": str(bucket.tokens),
                "last_refill_ts": str(bucket.last_refill_ts),
            },
        )
        if self._ttl > 0:
            self._client.expire(key, self._ttl)


__all__ = ["RedisRateLimitState"]
