"""
toolboundary._rate_limiter
--------------------------
Minimal in-memory sliding-window rate limiter.

Private module (leading underscore): this is an internal implementation
detail of Boundary, not part of the public API surface. Kept in-memory and
dependency-free on purpose -- ToolBoundary must add near-zero latency and
must not require Redis or a database to function for the common case of
a single-process agent.

For multi-process deployments, swap this out via the `store` hook in
Boundary (see boundary.py) -- e.g. backing it with Redis INCR/EXPIRE.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowRateLimiter:
    """Tracks timestamps of recent calls per key and enforces a max-per-window limit."""

    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check_and_record(self, key: str, max_calls: int, window_seconds: float) -> bool:
        """
        Returns True if the call is allowed (and records it).
        Returns False if the call would exceed max_calls within window_seconds.
        """
        now = time.monotonic()
        with self._lock:
            window = self._calls.setdefault(key, deque())

            # Drop timestamps outside the window
            cutoff = now - window_seconds
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= max_calls:
                return False

            window.append(now)
            return True

    def current_count(self, key: str, window_seconds: float) -> int:
        now = time.monotonic()
        with self._lock:
            window = self._calls.get(key, deque())
            cutoff = now - window_seconds
            return sum(1 for t in window if t >= cutoff)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._calls.clear()
            else:
                self._calls.pop(key, None)
