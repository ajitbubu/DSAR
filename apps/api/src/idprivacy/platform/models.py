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
    Integer,
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


# ---------- M1: intake, identity verification, Data Principal sessions --------------


class DataPrincipal(Base):
    __tablename__ = "data_principal"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_data_principal_tenant_id_id"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    enc_identifiers: Mapped[str] = mapped_column(Text, nullable=False)
    bidx_email: Mapped[str | None] = mapped_column(String(64))
    bidx_phone: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created_at()


class PrivacyRequest(Base):
    __tablename__ = "privacy_request"
    __table_args__ = (
        UniqueConstraint("tenant_id", "display_id", name="uq_privacy_request_display_id"),
        UniqueConstraint("tenant_id", "id", name="uq_privacy_request_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "data_principal_id"],
            ["data_principal.tenant_id", "data_principal.id"],
            name="fk_privacy_request_data_principal",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    display_id: Mapped[str] = mapped_column(String(20), nullable=False)
    data_principal_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False, default="WEB")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enc_full_name: Mapped[str] = mapped_column(Text, nullable=False)
    enc_submitted_identifiers: Mapped[str] = mapped_column(Text, nullable=False)
    residency_claim: Mapped[str] = mapped_column(String(16), nullable=False)
    submitted_at: Mapped[datetime] = _created_at()
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Pinned at jurisdiction time (M2); never changes for the life of the case.
    policy_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_pack.id")
    )
    workflow_code: Mapped[str | None] = mapped_column(String(32))


class RequestRight(Base):
    __tablename__ = "request_right"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_request_right_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    right_code: Mapped[str] = mapped_column(String(32), nullable=False)
    enc_details: Mapped[str | None] = mapped_column(Text)


class IdentityVerification(Base):
    __tablename__ = "identity_verification"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_identity_verification_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    resend_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class DpSession(Base):
    """Server-side Data Principal tracking session. Only the token's SHA-256 is stored."""

    __tablename__ = "dp_session"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_dp_session_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = _created_at()
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ---------- M2: policy packs, jurisdiction, identity resolution ---------------------


class PolicyPackRow(Base):
    """Global, immutable catalogue of published packs (not tenant-owned)."""

    __tablename__ = "policy_pack"
    __table_args__ = (UniqueConstraint("code", "version", name="uq_policy_pack_code_version"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TenantPolicyPack(Base):
    """Which pack versions a tenant has enabled, in evaluation order."""

    __tablename__ = "tenant_policy_pack"
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), primary_key=True
    )
    pack_code: Mapped[str] = mapped_column(String(32), primary_key=True)
    pack_version: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)


class JurisdictionDecision(Base):
    __tablename__ = "jurisdiction_decision"
    __table_args__ = (
        UniqueConstraint("tenant_id", "request_id", name="uq_jurisdiction_decision_request"),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_jurisdiction_decision_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_pack_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_pack.id")
    )
    regulation: Mapped[str | None] = mapped_column(String(32))
    policy_pack_version: Mapped[str | None] = mapped_column(String(32))
    inputs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()


class RequestIdentifier(Base):
    """Canonical identifier set for one request, with how strongly each is established."""

    __tablename__ = "request_identifier"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "request_id", "type", "bidx", name="uq_request_identifier_value"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_request_identifier_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    bidx: Mapped[str] = mapped_column(String(64), nullable=False)
    enc_value: Mapped[str] = mapped_column(Text, nullable=False)
    assurance: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = _created_at()


# ---------- M3: connectors and discovery --------------------------------------------


class ConnectorConfig(Base):
    """A tenant's connection to one source system. Credentials are referenced, never stored."""

    __tablename__ = "connector_config"
    __table_args__ = (
        UniqueConstraint("tenant_id", "connector_id", name="uq_connector_config_connector"),
        UniqueConstraint("tenant_id", "id", name="uq_connector_config_tenant_id_id"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    connector_id: Mapped[str] = mapped_column(String(40), nullable=False)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    credential_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = _created_at()


class DiscoveryJob(Base):
    __tablename__ = "discovery_job"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "request_id",
            "connector_config_id",
            "purpose",
            name="uq_discovery_job_per_connector",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_discovery_job_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_discovery_job_request",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "connector_config_id"],
            ["connector_config.tenant_id", "connector_config.id"],
            name="fk_discovery_job_connector",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    connector_config_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(40))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class DataMatch(Base):
    """A pointer to one source record. Never the record's content."""

    __tablename__ = "data_match"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "discovery_job_id", "source_record_ref", name="uq_data_match_per_job"
        ),
        UniqueConstraint("tenant_id", "id", name="uq_data_match_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "discovery_job_id"],
            ["discovery_job.tenant_id", "discovery_job.id"],
            name="fk_data_match_job",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    discovery_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    connector_id: Mapped[str] = mapped_column(String(40), nullable=False)
    source_record_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    record_type: Mapped[str] = mapped_column(String(64), nullable=False)
    data_categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    matched_on: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    content_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()


# ---------- M4: legal holds and retention decisions ---------------------------------


class LegalHold(Base):
    __tablename__ = "legal_hold"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_legal_hold_tenant_id_id"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    scope_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    matter_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = _created_at()
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class RetentionDecision(Base):
    """Append-only. The current decision for a match is the one nothing supersedes."""

    __tablename__ = "retention_decision"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_retention_decision_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "data_match_id"],
            ["data_match.tenant_id", "data_match.id"],
            name="fk_retention_decision_match",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    data_match_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(64))
    exception_code: Mapped[str | None] = mapped_column(String(32))
    exception_reason: Mapped[str | None] = mapped_column(Text)
    legal_hold_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = _created_at()


# ---------- M5: maker-checker approval ------------------------------------------------


class ApprovalSubmission(Base):
    """Recorded when a case enters PENDING_APPROVAL: who submitted which decision set."""

    __tablename__ = "approval_submission"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_approval_submission_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_approval_submission_request",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    submitted_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_set_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class Approval(Base):
    __tablename__ = "approval"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_approval_idempotency_key"),
        UniqueConstraint("tenant_id", "id", name="uq_approval_tenant_id_id"),
        ForeignKeyConstraint(
            ["tenant_id", "submission_id"],
            ["approval_submission.tenant_id", "approval_submission.id"],
            name="fk_approval_submission",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    submission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_set_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    submitted_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    approved_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()


# ---------- M6: fulfilment ---------------------------------------------------------


class FulfilmentTask(Base):
    __tablename__ = "fulfilment_task"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_fulfilment_task_key"),
        UniqueConstraint(
            "tenant_id", "data_match_id", "approval_id", name="uq_fulfilment_task_per_approval"
        ),
        UniqueConstraint("tenant_id", "id", name="uq_fulfilment_task_tenant_id_id"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    data_match_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    retention_decision_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    approval_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    connector_config_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skip_reason: Mapped[str | None] = mapped_column(String(200))
    receipt_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str | None] = mapped_column(String(20))
    last_error_code: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _created_at()


class ConnectorExecution(Base):
    """Append-only record of every connector call made for a fulfilment task."""

    __tablename__ = "connector_execution"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "fulfilment_task_id",
            "operation",
            "attempt_no",
            name="uq_connector_execution_attempt",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[uuid.UUID] = _tenant_fk()
    fulfilment_task_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(20), nullable=False)
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(40))
    receipt_id: Mapped[str | None] = mapped_column(String(64))
    replayed: Mapped[bool | None] = mapped_column()
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
