"""Shared fixtures.

Database tests run against the ``idprivacy_test`` database from Docker Compose (or CI
service containers), using the real least-privilege roles. The schema is rebuilt once
per session with Alembic. Each test creates its own tenants with random ids, so no
cleanup is needed (and the audit log can't be truncated anyway).
"""

import os
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import jwt
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from idprivacy.config import Settings
from idprivacy.main import create_app
from idprivacy.platform.models import AppUser, Role, Tenant, UserRole

API_DIR = Path(__file__).resolve().parents[1]
ISSUER = "https://idp.test.invalid/realms/idprivacy"
AUDIENCE = "idprivacy-api"
MASTER_KEY_B64 = "ZGV2LW9ubHktbWFzdGVyLWtleS0zMi1ieXRlcyEhISE="


def _db_url(role: str, default_pw: str) -> str:
    env = f"IDP_TEST_DATABASE_URL_{role.upper()}"
    host = os.environ.get("IDP_TEST_DB_HOST", "localhost:5432")
    return os.environ.get(
        env, f"postgresql+psycopg://idp_{role}:{default_pw}@{host}/idprivacy_test"
    )


MIGRATOR_URL = _db_url("migrator", "dev-migrator")
APP_URL = _db_url("app", "dev-app")
RELAY_URL = _db_url("relay", "dev-relay")


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "env": "test",
        "database_url_app": APP_URL,
        "database_url_relay": RELAY_URL,
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_jwks_url": "https://idp.test.invalid/jwks",
        "local_master_key": MASTER_KEY_B64,
    }
    values.update(overrides)
    return Settings(**values)


# ---------- Database ----------------------------------------------------------------


@pytest.fixture(scope="session")
def migrated_db() -> None:
    engine = create_engine(MIGRATOR_URL)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        if os.environ.get("IDP_REQUIRE_DB") == "1":
            raise
        pytest.skip("test database unavailable (run `make up-deps`); set IDP_REQUIRE_DB=1 to fail")
    finally:
        engine.dispose()
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.attributes["url"] = MIGRATOR_URL
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def migrator_engine(migrated_db: None) -> Iterator[Engine]:
    engine = create_engine(MIGRATOR_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def app_engine(migrated_db: None) -> Iterator[Engine]:
    engine = create_engine(APP_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def relay_engine(migrated_db: None) -> Iterator[Engine]:
    engine = create_engine(RELAY_URL)
    yield engine
    engine.dispose()


@pytest.fixture
def make_tenant(migrator_engine: Engine) -> Callable[[], uuid.UUID]:
    def _make() -> uuid.UUID:
        tid = uuid.uuid4()
        with Session(migrator_engine) as s, s.begin():
            s.add(Tenant(id=tid, slug=f"t-{tid.hex[:12]}", name="Test tenant", status="ACTIVE"))
        return tid

    return _make


@pytest.fixture
def provision_user(migrator_engine: Engine) -> Callable[..., tuple[uuid.UUID, str]]:
    """Create a user in ``tenant_id`` with ``roles``. Returns ``(user_id, subject)``."""

    def _provision(tenant_id: uuid.UUID, roles: list[str]) -> tuple[uuid.UUID, str]:
        subject = str(uuid.uuid4())
        with Session(migrator_engine) as s, s.begin():
            user = AppUser(
                tenant_id=tenant_id, idp_issuer=ISSUER, idp_subject=subject, status="ACTIVE"
            )
            s.add(user)
            s.flush()
            for code in roles:
                role = Role(tenant_id=tenant_id, code=code)
                s.add(role)
                s.flush()
                s.add(UserRole(tenant_id=tenant_id, user_id=user.id, role_id=role.id))
            return user.id, subject

    return _provision


# ---------- Tokens ------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def public_pem(rsa_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture
def make_token(rsa_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def _make(
        subject: str = "someone",
        *,
        key: Any = None,
        algorithm: str = "RS256",
        drop: tuple[str, ...] = (),
        **claims: Any,
    ) -> str:
        now = int(time.time())
        body: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "iat": now,
            "exp": now + 300,
        }
        body.update(claims)
        for k in drop:
            body.pop(k, None)
        return jwt.encode(body, key if key is not None else rsa_key, algorithm=algorithm)

    return _make


# ---------- App ---------------------------------------------------------------------


@pytest.fixture
def client(migrated_db: None, rsa_key: rsa.RSAPrivateKey) -> Iterator[TestClient]:
    app = create_app(
        make_settings(),
        key_resolver=lambda _token: rsa_key.public_key(),
        readiness_probes={},
    )
    with TestClient(app) as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
