"""Tests for the optional Redis shared rate-limiter / token-store backends.

These tests use fakeredis so CI never needs a live Redis server. They would
fail against the in-memory defaults alone: the behaviours under test are
exactly the shared-state contracts that only exist once the Redis backends
are present (cross-client visibility, SET NX single-use, fail-closed on
outage).
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock

import pytest

fakeredis = pytest.importorskip("fakeredis")

from toolboundary import (  # noqa: E402
    AccessMode,
    AutonomyLevel,
    Boundary,
    RateLimitExceeded,
    ToolPermission,
)
from toolboundary.network import NetworkEnforcer, UpstreamRoute  # noqa: E402
from toolboundary.redis_backend import (  # noqa: E402
    RedisSlidingWindowRateLimiter,
    RedisTokenStore,
)
from toolboundary.tokens import TokenIssuer  # noqa: E402


@pytest.fixture
def redis_client() -> Any:
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------------------------------------------------------------------
# RedisSlidingWindowRateLimiter
# ---------------------------------------------------------------------------


class TestRedisSlidingWindowRateLimiter:
    def test_allows_under_limit_and_denies_at_limit(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        assert limiter.check_and_record("k", max_calls=2, window_seconds=60) is True
        assert limiter.check_and_record("k", max_calls=2, window_seconds=60) is True
        assert limiter.check_and_record("k", max_calls=2, window_seconds=60) is False

    def test_window_expiry_frees_slots(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        assert limiter.check_and_record("k", max_calls=1, window_seconds=0.05) is True
        assert limiter.check_and_record("k", max_calls=1, window_seconds=0.05) is False
        time.sleep(0.06)
        assert limiter.check_and_record("k", max_calls=1, window_seconds=0.05) is True

    def test_keys_are_independent(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        assert limiter.check_and_record("a", max_calls=1, window_seconds=60) is True
        assert limiter.check_and_record("b", max_calls=1, window_seconds=60) is True
        assert limiter.check_and_record("a", max_calls=1, window_seconds=60) is False

    def test_current_count_and_reset(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        limiter.check_and_record("k", max_calls=5, window_seconds=60)
        limiter.check_and_record("k", max_calls=5, window_seconds=60)
        assert limiter.current_count("k", window_seconds=60) == 2
        limiter.reset("k")
        assert limiter.current_count("k", window_seconds=60) == 0

    def test_reset_all_clears_prefix(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client, key_prefix="tb:t:")
        limiter.check_and_record("a", max_calls=5, window_seconds=60)
        limiter.check_and_record("b", max_calls=5, window_seconds=60)
        limiter.reset()
        assert limiter.current_count("a", window_seconds=60) == 0
        assert limiter.current_count("b", window_seconds=60) == 0

    def test_shared_across_clients(self, redis_client: Any) -> None:
        """Two limiter instances on one Redis must share the window.

        This is the multi-replica contract: without Redis each process would
        allow max_calls independently and the effective limit would be
        max_calls * replica_count.
        """
        a = RedisSlidingWindowRateLimiter(client=redis_client)
        b = RedisSlidingWindowRateLimiter(client=redis_client)
        assert a.check_and_record("shared", max_calls=2, window_seconds=60) is True
        assert b.check_and_record("shared", max_calls=2, window_seconds=60) is True
        assert a.check_and_record("shared", max_calls=2, window_seconds=60) is False
        assert b.check_and_record("shared", max_calls=2, window_seconds=60) is False

    def test_zero_max_calls_denied(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        assert limiter.check_and_record("k", max_calls=0, window_seconds=60) is False

    def test_fail_closed_on_redis_error(self) -> None:
        broken = MagicMock()
        broken.register_script.side_effect = lambda *_a, **_k: MagicMock(
            side_effect=ConnectionError("redis down")
        )
        limiter = RedisSlidingWindowRateLimiter(client=broken, fail_closed=True)
        assert limiter.check_and_record("k", max_calls=10, window_seconds=60) is False
        assert limiter.current_count("k", window_seconds=60) == 2**31 - 1

    def test_fail_open_opt_in(self) -> None:
        broken = MagicMock()
        broken.register_script.side_effect = lambda *_a, **_k: MagicMock(
            side_effect=ConnectionError("redis down")
        )
        limiter = RedisSlidingWindowRateLimiter(client=broken, fail_closed=False)
        assert limiter.check_and_record("k", max_calls=10, window_seconds=60) is True
        assert limiter.current_count("k", window_seconds=60) == 0

    def test_rejects_both_url_and_client(self, redis_client: Any) -> None:
        with pytest.raises(ValueError, match="either redis_url or client"):
            RedisSlidingWindowRateLimiter(redis_url="redis://localhost", client=redis_client)

    def test_requires_url_or_client(self) -> None:
        with pytest.raises(ValueError, match="redis_url"):
            RedisSlidingWindowRateLimiter()

    def test_reset_swallows_redis_errors(self) -> None:
        broken = MagicMock()
        broken.register_script.side_effect = lambda *_a, **_k: MagicMock()
        broken.delete.side_effect = ConnectionError("redis down")
        limiter = RedisSlidingWindowRateLimiter(client=broken)
        limiter.reset("k")  # must not raise

    def test_redis_url_constructs_via_from_url(
        self, monkeypatch: pytest.MonkeyPatch, redis_client: Any
    ) -> None:
        import toolboundary.redis_backend as rb

        fake_mod = MagicMock()
        fake_mod.Redis.from_url.return_value = redis_client
        monkeypatch.setattr(rb, "_require_redis", lambda: fake_mod)

        limiter = RedisSlidingWindowRateLimiter(redis_url="redis://example:6379/0")
        fake_mod.Redis.from_url.assert_called_once_with(
            "redis://example:6379/0", decode_responses=True
        )
        assert limiter.check_and_record("k", max_calls=1, window_seconds=60) is True


# ---------------------------------------------------------------------------
# RedisTokenStore
# ---------------------------------------------------------------------------


class TestRedisTokenStore:
    def test_first_use_succeeds_second_fails(self, redis_client: Any) -> None:
        store = RedisTokenStore(client=redis_client)
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is True
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is False

    def test_is_used_reflects_state(self, redis_client: Any) -> None:
        store = RedisTokenStore(client=redis_client)
        assert store.is_used("tok-1") is False
        store.mark_used("tok-1", expires_at=time.time() + 30)
        assert store.is_used("tok-1") is True

    def test_expired_token_mark_refused(self, redis_client: Any) -> None:
        store = RedisTokenStore(client=redis_client)
        assert store.mark_used("tok-old", expires_at=time.time() - 1) is False
        assert store.is_used("tok-old") is False

    def test_shared_across_clients(self, redis_client: Any) -> None:
        a = RedisTokenStore(client=redis_client)
        b = RedisTokenStore(client=redis_client)
        assert a.mark_used("tok-shared", expires_at=time.time() + 30) is True
        assert b.mark_used("tok-shared", expires_at=time.time() + 30) is False
        assert b.is_used("tok-shared") is True

    def test_fail_closed_on_redis_error(self) -> None:
        broken = MagicMock()
        broken.set.side_effect = ConnectionError("redis down")
        broken.exists.side_effect = ConnectionError("redis down")
        store = RedisTokenStore(client=broken, fail_closed=True)
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is False
        assert store.is_used("tok-1") is True

    def test_fail_open_opt_in(self) -> None:
        broken = MagicMock()
        broken.set.side_effect = ConnectionError("redis down")
        broken.exists.side_effect = ConnectionError("redis down")
        store = RedisTokenStore(client=broken, fail_closed=False)
        assert store.mark_used("tok-1", expires_at=time.time() + 30) is True
        assert store.is_used("tok-1") is False


# ---------------------------------------------------------------------------
# Wiring into Boundary / NetworkEnforcer
# ---------------------------------------------------------------------------


class TestBoundaryAcceptsRedisLimiter:
    def test_boundary_enforces_shared_limit(self, redis_client: Any) -> None:
        limiter = RedisSlidingWindowRateLimiter(client=redis_client)
        b = Boundary(
            agent_name="agent-1",
            autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
            permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
            max_actions_per_hour=2,
            rate_limiter=limiter,
        )
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        with pytest.raises(RateLimitExceeded):
            b.check("read_db", access_mode=AccessMode.READ_ONLY)

    def test_two_boundaries_share_redis_limit(self, redis_client: Any) -> None:
        """Simulates two replicas: each has its own Boundary, one Redis."""
        shared = RedisSlidingWindowRateLimiter(client=redis_client)

        def make() -> Boundary:
            return Boundary(
                agent_name="agent-1",
                autonomy=AutonomyLevel.LIMITED_AUTONOMOUS,
                permissions=[ToolPermission("read_db", access_mode=AccessMode.READ_ONLY)],
                max_actions_per_hour=2,
                rate_limiter=shared,
            )

        a, b = make(), make()
        a.check("read_db", access_mode=AccessMode.READ_ONLY)
        b.check("read_db", access_mode=AccessMode.READ_ONLY)
        with pytest.raises(RateLimitExceeded):
            a.check("read_db", access_mode=AccessMode.READ_ONLY)


class TestNetworkEnforcerAcceptsRedisTokenStore:
    def test_replay_denied_across_store_instances(self, redis_client: Any) -> None:
        issuer = TokenIssuer(secret="test-secret", ttl_seconds=30)
        token = issuer.issue(agent_name="agent-1", tool_name="crm_api")
        wire = token.to_wire()

        store_a = RedisTokenStore(client=redis_client)
        store_b = RedisTokenStore(client=redis_client)
        routes = [UpstreamRoute("crm_api", "https://internal-crm.example.com")]

        enforcer_a = NetworkEnforcer(issuer, routes, token_store=store_a)
        enforcer_b = NetworkEnforcer(issuer, routes, token_store=store_b)

        allowed, reason, _url = enforcer_a.authorize_and_resolve("crm_api", wire)
        assert allowed is True
        assert reason == "ALLOWED"

        allowed, reason, _url = enforcer_b.authorize_and_resolve("crm_api", wire)
        assert allowed is False
        assert reason == "TOKEN_ALREADY_USED"


def test_missing_redis_extra_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing from redis_url without the redis package must fail loudly."""
    import builtins

    real_import = builtins.__import__

    def _block_redis(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "redis" or name.startswith("redis."):
            raise ImportError("simulated missing redis")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_redis)
    with pytest.raises(ImportError, match=r"toolboundary\[redis\]"):
        RedisSlidingWindowRateLimiter(redis_url="redis://localhost:6379/0")
