"""Database engines and tenant-scoped sessions.

The app connects as ``idp_app`` (no BYPASSRLS, not the table owner). Every unit of work
runs inside a transaction that sets ``app.tenant_id`` with ``set_config(..., true)``, which
is transaction-local, so pooled connections never carry tenant context over (ADR-0002).
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker


@dataclass(frozen=True)
class TenantContext:
    tenant_id: UUID


# Per process. FastAPI runs sync routes and dependencies on anyio's default thread
# limiter (40 tokens). Settings keeps max_inflight_requests below threads + connections,
# so threads waiting for a connection can never block every connection holder.
POOL_SIZE = 5
MAX_OVERFLOW = 5
POOL_TIMEOUT_SECONDS = 10
WORKER_THREADS = 40


@lru_cache(maxsize=4)
def make_engine(url: str) -> Engine:
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT_SECONDS,
    )


def set_tenant(session: Session, tenant_id: UUID) -> None:
    session.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(tenant_id)})


@contextmanager
def tenant_session(engine: Engine, ctx: TenantContext) -> Iterator[Session]:
    """Open a transaction bound to one tenant. Commits on success, rolls back on error."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session, session.begin():
        set_tenant(session, ctx.tenant_id)
        yield session
