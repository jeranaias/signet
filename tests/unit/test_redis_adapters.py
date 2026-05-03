"""Tests for Redis-backed state-store adapters.

Uses fakeredis (in-memory Redis-compatible) so we exercise the full
adapter behavior without spinning up a real Redis. Production
deployments swap in the real ``redis.Redis`` client; the protocol is
identical.
"""

from __future__ import annotations

import time

import fakeredis
import pytest

from signet.checks.rate_limit import RateLimitCheck, _Bucket
from signet.checks.redis_rate_limit_state import RedisRateLimitState
from signet.core.context import RequestContext
from signet.core.owner import Owner
from signet.server.redis_session_store import RedisSessionStore


@pytest.fixture
def redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


class TestRedisSessionStore:
    def test_get_or_create_persists(self, redis_client) -> None:
        store = RedisSessionStore(client=redis_client, ttl_seconds=60)
        session = store.get_or_create("sess-A")
        assert session.session_id == "sess-A"
        assert session.request_count == 0

        # A second instance with the same Redis sees the same session
        store2 = RedisSessionStore(client=redis_client)
        loaded = store2.get("sess-A")
        assert loaded is not None
        assert loaded.session_id == "sess-A"

    def test_save_updates_existing(self, redis_client) -> None:
        store = RedisSessionStore(client=redis_client, ttl_seconds=60)
        s = store.get_or_create("sess-B")
        s.touch()
        s.scratch["foo"] = "bar"
        store.save(s)

        loaded = store.get("sess-B")
        assert loaded is not None
        assert loaded.request_count == 1
        assert loaded.scratch == {"foo": "bar"}

    def test_delete_removes(self, redis_client) -> None:
        store = RedisSessionStore(client=redis_client)
        store.get_or_create("sess-C")
        store.delete("sess-C")
        assert store.get("sess-C") is None

    def test_get_unknown_session_returns_none(self, redis_client) -> None:
        store = RedisSessionStore(client=redis_client)
        assert store.get("nonexistent") is None

    def test_ttl_applied(self, redis_client) -> None:
        store = RedisSessionStore(client=redis_client, ttl_seconds=60)
        store.get_or_create("sess-D")
        ttl = redis_client.ttl(store._key("sess-D"))
        assert 0 < ttl <= 60


class TestRedisRateLimitState:
    def test_get_unknown_returns_none(self, redis_client) -> None:
        state = RedisRateLimitState(client=redis_client)
        assert state.get("human:bob") is None

    def test_set_and_get_roundtrip(self, redis_client) -> None:
        state = RedisRateLimitState(client=redis_client, ttl_seconds=10)
        bucket = _Bucket(tokens=42.5, last_refill_ts=time.monotonic())
        state.set("human:alice", bucket)

        loaded = state.get("human:alice")
        assert loaded is not None
        assert loaded.tokens == pytest.approx(42.5)
        assert loaded.last_refill_ts == pytest.approx(bucket.last_refill_ts)

    def test_two_state_instances_share_storage(self, redis_client) -> None:
        """Multiple workers see the same bucket — that's the whole point."""
        state_a = RedisRateLimitState(client=redis_client)
        state_b = RedisRateLimitState(client=redis_client)
        state_a.set("human:carol", _Bucket(tokens=10.0, last_refill_ts=100.0))

        loaded = state_b.get("human:carol")
        assert loaded is not None
        assert loaded.tokens == pytest.approx(10.0)


class TestRateLimitCheckWithRedisState:
    """End-to-end: RateLimitCheck wired against the Redis-backed state."""

    async def test_rate_limit_with_redis_state_works(self, redis_client) -> None:
        state = RedisRateLimitState(client=redis_client)
        check = RateLimitCheck(capacity=2, refill_per_second=0.001, state=state)
        ctx = RequestContext(owner=Owner.human("alice"))

        # First two requests allowed
        assert (await check.pre_request(ctx)).is_allow
        assert (await check.pre_request(ctx)).is_allow
        # Third blocked
        assert (await check.pre_request(ctx)).is_block
