"""FastAPI application factory."""

from collections.abc import Callable
from typing import Any

import boto3
import redis
import structlog
from fastapi import FastAPI
from sqlalchemy import text

from idprivacy.api.routes import audit, health, me
from idprivacy.config import Settings, get_settings
from idprivacy.domain.identity.otp import build_otp_provider
from idprivacy.platform.auth.oidc import KeyResolver, OidcVerifier, jwks_key_resolver
from idprivacy.platform.crypto import FieldCipher, build_key_provider
from idprivacy.platform.db import make_engine
from idprivacy.platform.logging import configure_logging


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
    engine = make_engine(settings.database_url_app.get_secret_value())
    app.state.settings = settings
    app.state.log = structlog.get_logger("idprivacy.api")
    app.state.app_engine = engine
    app.state.verifier = OidcVerifier(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        algorithms=settings.oidc_algorithms,
        key_resolver=key_resolver or jwks_key_resolver(settings.oidc_jwks_url),
    )
    assert settings.local_master_key is not None  # guaranteed by Settings validation
    app.state.cipher = FieldCipher(build_key_provider(settings.local_master_key.get_secret_value()))
    app.state.otp_provider = build_otp_provider(settings)
    app.state.readiness_probes = (
        readiness_probes if readiness_probes is not None else _probes(settings, engine)
    )

    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(audit.router)
    return app
