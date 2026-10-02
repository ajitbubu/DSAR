"""Discovery orchestration (M3).

1. ``start``: fire START_DISCOVERY and create one job per enabled connector.
2. ``run_job``: call the connector outside any DB transaction, then persist the
   matches (pointers and fingerprints only) and mark the job done.
3. ``finish_if_complete``: when every job has succeeded, fire DISCOVERY_FINISHED.

Every step is idempotent, so redelivered or retried tasks never duplicate matches.
Only identifiers whose assurance the pinned pack allows are ever sent to connectors.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from idprivacy_connector_sdk import (
    Connector,
    ConnectorError,
    DiscoveryRequest,
    Identifier,
    IdentifierType,
    Match,
)
from sqlalchemy import Engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.identity.resolution import CTX_REQUEST_IDENTIFIER
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    ConnectorConfig,
    DataMatch,
    DiscoveryJob,
    PrivacyRequest,
    RequestIdentifier,
)

ACTOR = SystemActor("system:discovery")
MAX_PAGES = 200
ConnectorFactory = Callable[[ConnectorConfig], Connector]


def _lock_request(session: Session, request_id: UUID) -> PrivacyRequest | None:
    return session.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
    ).scalar_one_or_none()


def start(
    session: Session, *, request_id: UUID, registry: PolicyRegistry, purpose: str = "INITIAL"
) -> list[UUID]:
    """Returns the ids of jobs that still need to run."""
    request = _lock_request(session, request_id)
    if request is None:
        return []
    if request.status == CaseStatus.JURISDICTION_DETERMINED:
        fire(session, request, "START_DISCOVERY", actor=ACTOR, registry=registry)
    if request.status != CaseStatus.DISCOVERY_IN_PROGRESS:
        return []
    configs = (
        session.execute(
            select(ConnectorConfig)
            .where(ConnectorConfig.enabled.is_(True))
            .order_by(ConnectorConfig.connector_id)
        )
        .scalars()
        .all()
    )
    for config in configs:
        session.execute(
            pg_insert(DiscoveryJob)
            .values(
                tenant_id=request.tenant_id,
                request_id=request.id,
                connector_config_id=config.id,
                purpose=purpose,
                status="PENDING",
                attempts=0,
                match_count=0,
            )
            .on_conflict_do_nothing(constraint="uq_discovery_job_per_connector")
        )
    jobs = (
        session.execute(
            select(DiscoveryJob.id).where(
                DiscoveryJob.request_id == request.id,
                DiscoveryJob.purpose == purpose,
                DiscoveryJob.status != "SUCCEEDED",
            )
        )
        .scalars()
        .all()
    )
    return list(jobs)


def discovery_identifiers(
    session: Session, *, request: PrivacyRequest, registry: PolicyRegistry, cipher: FieldCipher
) -> list[Identifier]:
    assert request.policy_pack_id is not None
    allowed = registry.by_id(session, request.policy_pack_id).pack.identity_resolution
    rows = session.execute(
        select(RequestIdentifier)
        .where(
            RequestIdentifier.request_id == request.id,
            RequestIdentifier.assurance.in_(allowed.discovery_assurance),
        )
        .order_by(RequestIdentifier.type)
    ).scalars()
    return [
        Identifier(
            type=IdentifierType(r.type),
            value=cipher.decrypt(r.tenant_id, CTX_REQUEST_IDENTIFIER, r.enc_value),
        )
        for r in rows
    ]


@dataclass(frozen=True)
class JobOutcome:
    status: str
    matches: int = 0
    error_code: str | None = None
    retryable: bool = False


def _collect(connector: Connector, identifiers: list[Identifier]) -> list[Match]:
    found: dict[str, Match] = {}
    token: str | None = None
    for _ in range(MAX_PAGES):
        page = connector.discover(
            DiscoveryRequest(identifiers=identifiers, page_size=100, page_token=token)
        )
        for m in page.matches:
            found.setdefault(m.source_record_ref, m)
        token = page.next_page_token
        if token is None:
            return list(found.values())
    raise ConnectorError("too many pages", retryable=False, code="too_many_pages")


def run_job(
    engine: Engine,
    *,
    tenant_id: UUID,
    job_id: UUID,
    factory: ConnectorFactory,
    registry: PolicyRegistry,
    cipher: FieldCipher,
) -> JobOutcome:
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        job = s.execute(
            select(DiscoveryJob).where(DiscoveryJob.id == job_id).with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if job is None:
            return JobOutcome("SKIPPED")  # another worker holds it, or it doesn't exist
        if job.status == "SUCCEEDED":
            return JobOutcome("SUCCEEDED", job.match_count)
        request = s.get(PrivacyRequest, job.request_id)
        config = s.get(ConnectorConfig, job.connector_config_id)
        assert request is not None and config is not None
        identifiers = discovery_identifiers(s, request=request, registry=registry, cipher=cipher)
        job.status, job.attempts = "RUNNING", job.attempts + 1
        job.started_at, job.error_code = datetime.now(UTC), None
        connector_id = config.connector_id
        connector = factory(config)

    try:
        matches = _collect(connector, identifiers) if identifiers else []
    except ConnectorError as exc:
        with tenant_session(engine, ctx) as s:
            job = s.get(DiscoveryJob, job_id)
            assert job is not None
            job.status, job.error_code = "FAILED", exc.code
            job.finished_at = datetime.now(UTC)
            audit.append(
                s,
                tenant_id=tenant_id,
                actor_type="CONNECTOR",
                actor_ref=f"connector:{connector_id}",
                action="discovery.job_failed",
                object_type="discovery_job",
                object_id=job_id,
                details={
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "attempt": job.attempts,
                },
            )
        return JobOutcome("FAILED", error_code=exc.code, retryable=exc.retryable)

    with tenant_session(engine, ctx) as s:
        job = s.get(DiscoveryJob, job_id)
        assert job is not None
        for m in matches:
            s.execute(
                pg_insert(DataMatch)
                .values(
                    tenant_id=tenant_id,
                    discovery_job_id=job_id,
                    request_id=job.request_id,
                    connector_id=connector_id,
                    source_record_ref=m.source_record_ref,
                    record_type=m.record_type,
                    data_categories=list(m.data_categories),
                    matched_on=[t.value for t in m.matched_on],
                    content_fingerprint=m.content_fingerprint,
                    attributes=dict(m.attributes),
                )
                .on_conflict_do_nothing(constraint="uq_data_match_per_job")
            )
        job.status, job.match_count = "SUCCEEDED", len(matches)
        job.finished_at = datetime.now(UTC)
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="CONNECTOR",
            actor_ref=f"connector:{connector_id}",
            action="discovery.job_succeeded",
            object_type="discovery_job",
            object_id=job_id,
            details={
                "matches": len(matches),
                "identifier_count": len(identifiers),
                "record_types": sorted({m.record_type for m in matches}),
            },
        )
    return JobOutcome("SUCCEEDED", len(matches))


def finish_if_complete(session: Session, *, request_id: UUID, registry: PolicyRegistry) -> bool:
    request = _lock_request(session, request_id)
    if request is None or request.status != CaseStatus.DISCOVERY_IN_PROGRESS:
        return False
    statuses = (
        session.execute(
            select(DiscoveryJob.status).where(
                DiscoveryJob.request_id == request_id, DiscoveryJob.purpose == "INITIAL"
            )
        )
        .scalars()
        .all()
    )
    if any(s != "SUCCEEDED" for s in statuses):
        return False
    fire(session, request, "DISCOVERY_FINISHED", actor=ACTOR, registry=registry)
    return True


def retry_failed(session: Session, *, request_id: UUID, max_attempts: int | None = None) -> int:
    """Reset FAILED jobs so the next run retries them. Returns how many were reset.

    Automatic retries pass ``max_attempts``: a job that has used them up stays FAILED with
    its error code, so staff see why the case is stuck and can retry it themselves
    (a staff retry passes no cap).
    """
    query = select(DiscoveryJob).where(
        DiscoveryJob.request_id == request_id, DiscoveryJob.status == "FAILED"
    )
    if max_attempts is not None:
        query = query.where(DiscoveryJob.attempts < max_attempts)
    jobs = session.execute(query.with_for_update()).scalars().all()
    for job in jobs:
        job.status, job.error_code = "PENDING", None
    return len(jobs)


def after_discovery(session: Session, *, request_id: UUID, registry: PolicyRegistry) -> str | None:
    """Finish discovery, then run the next step only if the pinned workflow defines one.

    Erasure-style workflows define RETENTION_EVALUATED after DISCOVERY_COMPLETE; others
    (e.g. access) go straight to analyst review. The pack decides, not this code.
    """
    from idprivacy.domain.policy.workflow import target_of
    from idprivacy.domain.retention import service as retention

    if not finish_if_complete(session, request_id=request_id, registry=registry):
        return None
    request = session.get(PrivacyRequest, request_id)
    assert request is not None
    if target_of(session, request, "RETENTION_EVALUATED", registry) is not None:
        retention.evaluate_case(session, request=request, registry=registry)
        return "RETENTION_EVALUATED"
    return "DISCOVERY_COMPLETE"
