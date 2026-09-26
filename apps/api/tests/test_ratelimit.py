import os
import uuid

import pytest
import redis

from idprivacy.platform.ratelimit import (
    Limit,
    MemoryRateLimiter,
    RateLimiter,
    RateLimitExceeded,
    RedisRateLimiter,
)

REDIS_URL = os.environ.get("IDP_TEST_REDIS_URL", "redis://localhost:16379/15")


def _redis_limiter() -> RateLimiter:
    client = redis.Redis.from_url(REDIS_URL, socket_timeout=1)
    try:
        client.ping()
    except redis.ConnectionError:
        if os.environ.get("IDP_REQUIRE_DB") == "1":
            raise
        pytest.skip("redis unavailable")
    return RedisRateLimiter(client)


@pytest.fixture(params=["memory", "redis"])
def limiter(request: pytest.FixtureRequest) -> RateLimiter:
    return MemoryRateLimiter() if request.param == "memory" else _redis_limiter()


def test_allows_up_to_limit_then_raises(limiter: RateLimiter) -> None:
    limit = Limit(f"test:{uuid.uuid4()}", 3, 60)
    for _ in range(3):
        limiter.hit(limit, "198.51.100.1")
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.hit(limit, "198.51.100.1")
    assert 1 <= exc.value.retry_after <= 60


def test_subjects_are_independent(limiter: RateLimiter) -> None:
    limit = Limit(f"test:{uuid.uuid4()}", 1, 60)
    limiter.hit(limit, "a")
    limiter.hit(limit, "b")


def test_redis_keys_do_not_contain_subject() -> None:
    limiter = _redis_limiter()
    scope = f"test:{uuid.uuid4()}"
    limiter.hit(Limit(scope, 5, 60), "priya@example.in")
    client = redis.Redis.from_url(REDIS_URL)
    keys = [k.decode() for k in client.scan_iter(f"rl:{scope}:*")]
    assert len(keys) == 1 and "priya" not in keys[0]
