"""Phase 5: token-bucket rate limiter (unit) + the opt-in middleware.

The pure :class:`~app.ratelimit.TokenBucketRateLimiter` allows a burst up to the
configured budget then denies. Wired through ``RateLimitMiddleware`` (enabled via
monkeypatch on the shared settings singleton with a tiny per-minute budget),
hammering an authenticated endpoint eventually returns 429, while ``/health`` is
always exempt.
"""

from app.config import settings as app_settings
from app.ratelimit import TokenBucketRateLimiter


def test_token_bucket_allows_burst_then_blocks():
    rl = TokenBucketRateLimiter(rate_per_minute=3)

    # The first `rate` calls for a key are allowed (full burst capacity)...
    assert [rl.check("client-a").allowed for _ in range(3)] == [True, True, True]

    # ...the next is denied, with a positive retry hint and the echoed limit.
    denied = rl.check("client-a")
    assert denied.allowed is False
    assert denied.retry_after > 0
    assert denied.limit == 3
    assert denied.remaining == 0

    # A different client has an independent bucket.
    assert rl.check("client-b").allowed is True


def test_zero_rate_is_coerced_not_fatal():
    rl = TokenBucketRateLimiter(rate_per_minute=0)
    # Coerced to a minimum of 1 rather than dividing by zero / blocking all.
    assert rl.rate_per_minute == 1
    assert rl.check("k").allowed is True


def test_middleware_eventually_429s(client, auth, monkeypatch):
    monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(app_settings, "RATE_LIMIT_PER_MINUTE", 3)

    statuses = []
    for _ in range(25):
        resp = client.get("/auth/me", headers=auth["headers"])
        statuses.append(resp.status_code)

    assert 200 in statuses  # the first few within budget succeed
    assert 429 in statuses  # the budget is exhausted and requests are throttled

    # The throttled response advertises a Retry-After.
    throttled = client.get("/auth/me", headers=auth["headers"])
    assert throttled.status_code == 429
    assert int(throttled.headers["Retry-After"]) >= 1


def test_health_is_exempt_from_rate_limiting(client, monkeypatch):
    monkeypatch.setattr(app_settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(app_settings, "RATE_LIMIT_PER_MINUTE", 1)

    # /health is an infra probe and must never be throttled.
    for _ in range(15):
        assert client.get("/health").status_code == 200
