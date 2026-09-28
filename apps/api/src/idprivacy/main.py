"""FastAPI application factory."""

from collections.abc import Callable
from typing import Any

import boto3
import redis
import structlog
from fastapi import FastAPI
from sqlalchemy import text

from idprivacy.api.routes import audit, cases, health, me, policy, public, test_support
from idprivacy.config import Settings, get_settings
from idprivacy.domain.identity.otp import build_otp_provider
from idprivacy.platform.auth.oidc import KeyResolver, OidcVerifier, jwks_key_resolver
from idprivacy.platform.http import BodySizeLimitMiddleware, install_problem_handlers
from idprivacy.platform.logging import configure_logging
from idprivacy.platform.ratelimit import MemoryRateLimiter, RateLimiter, RedisRateLimiter
from idprivacy.runtime import build_services


def _probes(settings: Settings, engine: Any) -> dict[str, Callable[[], None]]:
    def db() -> None:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

    def cache() -> None:
        redis.Redis.from_url(settings.redis_url, socket_timeout=2).ping()

    def storage() -> None:
        s3 = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            region_name="us-east-1",
            aws_access_key_id=(
                settings.s3_access_key_id.get_secret_value() if settings.s3_access_key_id else None
            ),
            aws_secret_access_key=(
                settings.s3_secret_access_key.get_secret_value()
                if settings.s3_secret_access_key
                else None
            ),
        )
        s3.head_bucket(Bucket=settings.s3_bucket)

    return {"database": db, "redis": cache, "storage": storage}


def _rate_limiter(settings: Settings) -> RateLimiter:
    if settings.rate_limiter == "memory":
        return MemoryRateLimiter()
    return RedisRateLimiter(redis.Redis.from_url(settings.redis_url, socket_timeout=2))


def create_app(
    settings: Settings | None = None,
    *,
    key_resolver: KeyResolver | None = None,
    readiness_probes: dict[str, Callable[[], None]] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()

    app = FastAPI(
        title="ID-PRIVACY DPAR/DSAR Automation API",
        version="0.1.0",
        docs_url="/docs" if settings.env in {"local", "test"} else None,
        redoc_url=None,
    )
    svc = build_services(settings)
    engine = svc.engine
    app.state.settings = settings
    app.state.log = structlog.get_logger("idprivacy.api")
    app.state.app_engine = engine
    app.state.verifier = OidcVerifier(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        algorithms=settings.oidc_algorithms,
        key_resolver=key_resolver or jwks_key_resolver(settings.oidc_jwks_url),
    )
    app.state.services = svc
    app.state.keys = svc.keys
    app.state.cipher = svc.cipher
    app.state.otp_provider = build_otp_provider(settings)
    app.state.rate_limiter = _rate_limiter(settings)
    app.state.readiness_probes = (
        readiness_probes if readiness_probes is not None else _probes(settings, engine)
    )

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    install_problem_handlers(app)
    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(audit.router)
    app.include_router(public.router)
    app.include_router(policy.router)
    app.include_router(cases.router)
    if settings.env == "test" and settings.otp_provider == "mock":
        app.include_router(test_support.router)
    return app
