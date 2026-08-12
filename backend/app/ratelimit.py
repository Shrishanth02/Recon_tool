"""A pure, thread-safe, in-memory token-bucket rate limiter (stdlib only).

Used by :class:`app.middleware.RateLimitMiddleware`. Each client (keyed by IP or
authenticated principal) gets an independent bucket that refills continuously at
``rate_per_minute / 60`` tokens per second up to a burst capacity. A request
consumes one token; when the bucket is empty the request is denied and the
caller is told how many seconds to wait via ``retry_after``.

The limiter holds no framework or network dependencies, so it is trivially unit
testable and safe to import anywhere.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = ["TokenBucketRateLimiter", "RateLimitDecision"]


@dataclass(frozen=True)
class RateLimitDecision:
    """The outcome of a single :meth:`TokenBucketRateLimiter.check`.

    ``allowed`` is whether the request may proceed. ``remaining`` is the whole
    number of tokens left in the bucket after this call. ``retry_after`` is the
    number of seconds until at least one token is available (``0.0`` when the
    request was allowed). ``limit`` echoes the configured per-minute rate.
    """

    allowed: bool
    remaining: int
    retry_after: float
    limit: int


class TokenBucketRateLimiter:
    """A continuous-refill token bucket keyed by an arbitrary client id.

    Parameters
    ----------
    rate_per_minute:
        Sustained request budget per client per minute (also the bucket's burst
        capacity). Values ``<= 0`` are coerced to ``1`` so the limiter never
        divides by zero or blocks every request outright.
    capacity:
        Optional burst capacity override. Defaults to ``rate_per_minute``.

    The implementation is thread-safe (a single lock guards the bucket table)
    and monotonic-clock based, so it is immune to wall-clock adjustments.
    """

    def __init__(self, rate_per_minute: int, capacity: int | None = None) -> None:
        self.rate_per_minute = max(1, int(rate_per_minute))
        self.capacity = float(
            max(1, int(capacity)) if capacity is not None else self.rate_per_minute
        )
        # tokens refilled per second.
        self._refill_per_sec = self.rate_per_minute / 60.0
        # client_key -> (tokens, last_refill_monotonic)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def check(self, key: str, cost: float = 1.0) -> RateLimitDecision:
        """Attempt to consume ``cost`` tokens for ``key``.

        Returns a :class:`RateLimitDecision`. This both reads and mutates the
        bucket state atomically under the lock.
        """
        cost = max(0.0, float(cost))
        now = self._now()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            # Continuous refill since we last saw this client.
            elapsed = max(0.0, now - last)
            tokens = min(self.capacity, tokens + elapsed * self._refill_per_sec)

            if tokens >= cost:
                tokens -= cost
                self._buckets[key] = (tokens, now)
                return RateLimitDecision(
                    allowed=True,
                    remaining=int(tokens),
                    retry_after=0.0,
                    limit=self.rate_per_minute,
                )

            # Not enough tokens: compute the wait for the shortfall.
            deficit = cost - tokens
            retry_after = (
                deficit / self._refill_per_sec if self._refill_per_sec > 0 else 60.0
            )
            self._buckets[key] = (tokens, now)
            return RateLimitDecision(
                allowed=False,
                remaining=int(tokens),
                retry_after=retry_after,
                limit=self.rate_per_minute,
            )

    def reset(self, key: str | None = None) -> None:
        """Forget one client's bucket, or all buckets when ``key`` is ``None``."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)
