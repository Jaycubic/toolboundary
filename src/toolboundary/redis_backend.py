"""
toolboundary.redis_backend
--------------------------
Optional Redis-backed implementations of the in-memory rate limiter and
token store, for multi-process / multi-replica agent deployments.

Why this module exists
----------------------
`SlidingWindowRateLimiter` and `InMemoryTokenStore` are deliberately
process-local and dependency-free -- that is the right default for a
single-process agent. Across replicas those defaults silently under-count
(rate limits) or allow replay (single-use tokens), because each process
only sees its own state.

This module provides drop-in replacements that share state through Redis
so every replica participates in the same sliding window and the same
single-use ledger. It is never imported by the core package; install the
optional extra and pass the objects in explicitly:

    pip install toolboundary[redis]

    from toolboundary.redis_backend import RedisSlidingWindowRateLimiter, RedisTokenStore

    limiter = RedisSlidingWindowRateLimiter(redis_url="redis://localhost:6379/0")
    store = RedisTokenStore(redis_url="redis://localhost:6379/0")

    boundary = Boundary(..., rate_limiter=limiter)
    enforcer = NetworkEnforcer(issuer, routes, token_store=store)

Fail-closed by design
---------------------
Every public method that participates in an allow/deny decision treats a
Redis outage (connection error, timeout, unexpected reply) as a *deny*:

- `check_and_record` returns False -- the call is rate-limited rather than
  silently allowed when we cannot observe the shared counter.
- `mark_used` returns False -- the token is treated as already consumed,
  so a network hop that cannot record single-use state is refused rather
  than opened to replay.
- `is_used` returns True -- assume consumed when we cannot ask Redis.

Failing open here would be worse than the in-memory default: a Redis
blip would briefly disable the very controls this module exists to
enforce across replicas. Operators who prefer fail-open can catch the
logged errors and wrap these classes; the library itself will not.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any

_logger = logging.getLogger("toolboundary.redis_backend")

# Atomic sliding-window check+record.
#
# Why Lua rather than a MULTI/EXEC pipeline: under concurrent writers a
# non-atomic read-then-write race lets N replicas each observe count < max
# and all record a call, overshooting the limit by up to the replica
# count. A single EVAL keeps remove/count/add/expire indivisible.
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max_calls = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count >= max_calls then
  return 0
end
redis.call('ZADD', key, now, member)
-- TTL must outlive the window so a quiet key eventually expires, but
-- still covers the full window for the most recent call.
if ttl > 0 then
  redis.call('EXPIRE', key, ttl)
end
return 1
"""

_CURRENT_COUNT_LUA = """
local key = KEYS[1]
local cutoff = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
return redis.call('ZCARD', key)
"""


def _require_redis() -> Any:
    """
    Import redis lazily so `import toolboundary.redis_backend` is what
    surfaces the missing-extra error, not `import toolboundary` itself.
    Core stays dependency-free; only users who opt into this module pay.
    """
    try:
        import redis
    except ImportError as exc:  # pragma: no cover - exercised via dedicated test
        raise ImportError(
            "toolboundary.redis_backend requires the 'redis' package. "
            "Install it with: pip install toolboundary[redis]"
        ) from exc
    return redis


def _make_client(
    *,
    redis_url: str | None,
    client: Any | None,
) -> Any:
    if client is not None and redis_url is not None:
        raise ValueError("Pass either redis_url or client, not both.")
    if client is not None:
        # Injected clients (redis.Redis, fakeredis, test doubles) skip the
        # import gate so tests can exercise fail-closed paths with a mock
        # without needing a live server. Production callers using redis_url
        # still hit _require_redis() below.
        return client
    if redis_url is None:
        raise ValueError("Provide redis_url=... or client=...")
    redis = _require_redis()
    return redis.Redis.from_url(redis_url, decode_responses=True)


class RedisSlidingWindowRateLimiter:
    """
    Redis-backed sliding-window rate limiter with the same public interface
    as `toolboundary._rate_limiter.SlidingWindowRateLimiter`.

    Drop-in for `Boundary(rate_limiter=...)`. Uses a Redis sorted set per
    key (score = wall-clock timestamp) so the window is shared across
    processes. Wall-clock (`time.time`) is intentional: `time.monotonic`
    is process-local and cannot coordinate replicas.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        client: Any | None = None,
        key_prefix: str = "toolboundary:rl:",
        fail_closed: bool = True,
    ) -> None:
        self._client = _make_client(redis_url=redis_url, client=client)
        self._key_prefix = key_prefix
        self._fail_closed = fail_closed
        self._script = self._client.register_script(_SLIDING_WINDOW_LUA)
        self._count_script = self._client.register_script(_CURRENT_COUNT_LUA)

    def _redis_key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"

    def check_and_record(self, key: str, max_calls: int, window_seconds: float) -> bool:
        """
        Returns True if the call is allowed (and records it).
        Returns False if the call would exceed max_calls within window_seconds,
        or if Redis is unreachable and fail_closed is True.
        """
        if max_calls <= 0:
            return False
        now = time.time()
        cutoff = now - window_seconds
        # Keep the key at least as long as the window, plus a small buffer so
        # a call at the trailing edge is not GC'd before current_count can see it.
        ttl = max(1, int(window_seconds) + 1)
        member = f"{now:.6f}:{secrets.token_hex(4)}"
        try:
            allowed = self._script(
                keys=[self._redis_key(key)],
                args=[now, cutoff, int(max_calls), member, ttl],
            )
            return bool(int(allowed))
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "Redis rate-limiter check failed for key=%r; failing %s: %s",
                key,
                "closed" if self._fail_closed else "open",
                exc,
            )
            return not self._fail_closed

    def current_count(self, key: str, window_seconds: float) -> int:
        now = time.time()
        cutoff = now - window_seconds
        try:
            count = self._count_script(keys=[self._redis_key(key)], args=[cutoff])
            return int(count)
        except Exception as exc:  # noqa: BLE001
            _logger.error("Redis rate-limiter current_count failed for key=%r: %s", key, exc)
            # Fail-closed for observability: report the limit as saturated so
            # callers that gate on current_count do not under-count during an outage.
            return 0 if not self._fail_closed else 2**31 - 1

    def reset(self, key: str | None = None) -> None:
        """
        Delete one key, or every key under this limiter's prefix.

        Scanning by prefix is intentional for operator/test use; production
        hot paths should reset a single known key. On Redis error we log and
        swallow -- reset is best-effort cleanup, not an allow/deny decision.
        """
        try:
            if key is not None:
                self._client.delete(self._redis_key(key))
                return
            # SCAN avoids blocking Redis the way KEYS would on a large keyspace.
            pattern = f"{self._key_prefix}*"
            cursor: int | str = 0
            while True:
                cursor, batch = self._client.scan(cursor=cursor, match=pattern, count=100)
                if batch:
                    self._client.delete(*batch)
                if int(cursor) == 0:
                    break
        except Exception as exc:  # noqa: BLE001
            _logger.error("Redis rate-limiter reset failed for key=%r: %s", key, exc)


class RedisTokenStore:
    """
    Redis-backed single-use token ledger with the same public interface as
    `toolboundary.tokens.InMemoryTokenStore`.

    Drop-in for `NetworkEnforcer(..., token_store=...)`. Uses SET NX with a
    TTL derived from the token's expires_at so (a) the first writer wins
    atomically across replicas and (b) expired entries disappear without a
    separate GC pass.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        client: Any | None = None,
        key_prefix: str = "toolboundary:tok:",
        fail_closed: bool = True,
    ) -> None:
        self._client = _make_client(redis_url=redis_url, client=client)
        self._key_prefix = key_prefix
        self._fail_closed = fail_closed

    def _redis_key(self, token_id: str) -> str:
        return f"{self._key_prefix}{token_id}"

    def mark_used(self, token_id: str, expires_at: float) -> bool:
        """
        Returns True if this is the first use, False if already used.

        On Redis failure with fail_closed=True, returns False (treat as
        already used) so a replay cannot slip through an outage. SET NX is
        the Redis equivalent of the in-memory `if token_id in self._used`
        check, made atomic across processes.
        """
        ttl = int(expires_at - time.time()) + 1
        if ttl <= 0:
            # Token already past its expiry; refuse rather than store a
            # zero/negative TTL key that Redis would reject or keep forever.
            return False
        try:
            created = self._client.set(self._redis_key(token_id), "1", nx=True, ex=ttl)
            return bool(created)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "Redis token-store mark_used failed for token_id=%r; failing %s: %s",
                token_id,
                "closed" if self._fail_closed else "open",
                exc,
            )
            # fail_closed -> False (deny / treat as used)
            # fail_open   -> True  (allow / pretend first use -- operator opt-in only)
            return not self._fail_closed

    def is_used(self, token_id: str) -> bool:
        try:
            return bool(self._client.exists(self._redis_key(token_id)))
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "Redis token-store is_used failed for token_id=%r; failing %s: %s",
                token_id,
                "closed" if self._fail_closed else "open",
                exc,
            )
            return self._fail_closed
