"""SQLAlchemy models for the M0 baseline.

Every tenant-owned table carries ``tenant_id``. Child tables reference parents through
composite ``(tenant_id, id)`` foreign keys so a row can't point into another tenant
(ADR-0002). Later milestones add their own tables alongside these.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _tenant_fk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("tenant.id"), nullable=False, index=True)


class Tenant(Base):
    __tablename__ = "tenant"
    id: Mapped[uuid.UUID] = _uuid_pk()
    slug: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")
    data_region: Mapped[str | None] = mapped_column(String(32))  # decision D-6
    created_at: Mapped[datetime] = _created_at()


class Role(Base):
    __tablename__ = "role"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code"),
        UniqueConstraint("tenant_id", "id", name="uq_role_tenant_id_id"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class AppUser(Base):
    __tablename__ = "app_user"
    __table_args__ = (
        # One staff identity maps to exactly one tenant in the MVP (see D-1).
        UniqueConstraint("idp_issuer", "idp_subject", name="uq_app_user_idp_identity"),
        UniqueConstraint("tenant_id", "id", name="uq_app_user_tenant_id_id"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    idp_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    idp_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    enc_email: Mapped[str | None] = mapped_column(Text)
    display_name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = _created_at()


class UserRole(Base):
    __tablename__ = "user_role"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["app_user.tenant_id", "app_user.id"],
            name="fk_user_role_user",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "role_id"], ["role.tenant_id", "role.id"], name="fk_user_role_role"
        ),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)


class TenantAuditHead(Base):
    __tablename__ = "tenant_audit_head"
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), primary_key=True
    )
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditEvent(Base):
    """Append-only. UPDATE/DELETE/TRUNCATE are revoked and blocked by trigger (ADR-0004)."""

    __tablename__ = "audit_event"
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)


class OutboxMessage(Base):
    __tablename__ = "outbox"
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    topic: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
