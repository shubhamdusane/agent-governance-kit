"""In-memory sliding window rate limiter. Single-process. For distributed, swap for Redis."""

from __future__ import annotations

import time
from collections import deque
from threading import Lock


class RateLimiter:
    """Sliding-window rate limiter.

    Args:
        max_calls: max calls allowed
        window_seconds: window size in seconds
    """

    def __init__(self, max_calls: int, window_seconds: float = 60.0):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str = "default") -> bool:
        """Return True if call is allowed, False if rate limit hit."""
        now = time.monotonic()
        with self._lock:
            q = self._calls.setdefault(key, deque())
            # Purge old entries.
            cutoff = now - self.window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_calls:
                return False
            q.append(now)
            return True

    def reset(self, key: str = "default") -> None:
        with self._lock:
            self._calls.pop(key, None)

    @classmethod
    def parse_spec(cls, spec: str) -> "RateLimiter":
        """Parse '50/min' or '100/hour' into a RateLimiter."""
        count_str, _, period = spec.partition("/")
        count = int(count_str)
        period = period.strip().lower()
        seconds = {
            "sec": 1, "second": 1, "seconds": 1,
            "min": 60, "minute": 60, "minutes": 60,
            "hour": 3600, "hr": 3600, "hours": 3600,
            "day": 86400, "days": 86400,
        }.get(period, 60)
        return cls(max_calls=count, window_seconds=float(seconds))
