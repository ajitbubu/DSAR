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


def test_each_staff_user_is_rate_limited_on_their_own(
    migrated_db: None,
    rsa_key,
    make_tenant,
    provision_user,
    make_token,  # type: ignore[no-untyped-def]
) -> None:
    # Regression: one authenticated staff user could flood read endpoints and take the
    # whole API's capacity from every tenant (CSO finding 27c0d030f50e).
    from fastapi.testclient import TestClient

    from idprivacy.main import create_app
    from idprivacy.platform.storage import MemoryBlobStore
    from tests.conftest import bearer, make_settings

    app = create_app(
        make_settings(rate_limit_staff_per_user="3/60"),
        key_resolver=lambda _token: rsa_key.public_key(),
        readiness_probes={},
        blob_store=MemoryBlobStore(),
    )
    tenant = make_tenant()
    _, flooder = provision_user(tenant, ["AUDITOR"])
    _, colleague = provision_user(tenant, ["AUDITOR"])
    with TestClient(app) as c:
        codes = [c.get("/v1/me", headers=bearer(make_token(flooder))).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        limited = c.get("/v1/me", headers=bearer(make_token(flooder)))
        assert 1 <= int(limited.headers["retry-after"]) <= 60
        assert c.get("/v1/me", headers=bearer(make_token(colleague))).status_code == 200
