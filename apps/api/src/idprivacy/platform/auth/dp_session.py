"""Server-side Data Principal tracking sessions (ADR-0003).

The raw token (256 bits from ``secrets``) goes back to the BFF once and is never stored.
Only its SHA-256 is persisted, which is enough for a high-entropy random token.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.orm import Session

from idprivacy.config import Settings
from idprivacy.platform.models import DpSession


@dataclass(frozen=True)
class DataPrincipalPrincipal:
    tenant_id: UUID
    request_id: UUID
    session_id: UUID


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(
    session: Session, *, tenant_id: UUID, request_id: UUID, settings: Settings
) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    absolute = now + timedelta(seconds=settings.dp_session_max_seconds)
    idle = min(now + timedelta(seconds=settings.dp_session_idle_seconds), absolute)
    session.add(
        DpSession(
            tenant_id=tenant_id,
            request_id=request_id,
            token_hash=token_hash(token),
            idle_expires_at=idle,
            absolute_expires_at=absolute,
        )
    )
    session.flush()
    return token, idle


def touch(session: Session, session_id: UUID, settings: Settings) -> None:
    """Slide the idle expiry, never past the absolute expiry."""
    row = session.get(DpSession, session_id)
    if row is None:
        return
    idle = datetime.now(UTC) + timedelta(seconds=settings.dp_session_idle_seconds)
    session.execute(
        update(DpSession)
        .where(DpSession.id == session_id)
        .values(idle_expires_at=min(idle, row.absolute_expires_at))
    )
