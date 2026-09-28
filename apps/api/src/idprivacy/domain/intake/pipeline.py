"""Post-verification pipeline (M2), run by the worker for the ``case.verified`` topic.

Steps (one transaction):
1. Identity resolution → canonical identifier set with assurance levels.
2. Jurisdiction decision → pin the case to a policy pack version and workflow.
3. Hand off: executable rights → JURISDICTION_DETERMINED; others → manual handling.

Idempotent: a case that is no longer VERIFIED is left alone.
"""

from datetime import timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus, IntakeEvent, transition
from idprivacy.domain.identity import resolution
from idprivacy.domain.policy.jurisdiction import Decision, JurisdictionInputs, decide
from idprivacy.domain.policy.registry import PolicyRegistry, PublishedPack
from idprivacy.platform import outbox
from idprivacy.platform.crypto import FieldCipher, KeyProvider
from idprivacy.platform.models import (
    IdentityVerification,
    JurisdictionDecision,
    PrivacyRequest,
    RequestRight,
    Tenant,
    TenantPolicyPack,
)

ACTOR = "system:intake-pipeline"


def _candidates(session: Session, registry: PolicyRegistry, tenant_id: UUID) -> list[PublishedPack]:
    enabled = session.execute(
        select(TenantPolicyPack)
        .where(TenantPolicyPack.tenant_id == tenant_id, TenantPolicyPack.enabled.is_(True))
        .order_by(TenantPolicyPack.priority, TenantPolicyPack.pack_code)
    ).scalars()
    packs = []
    for row in enabled:
        published = registry.get(session, row.pack_code, row.pack_version)
        if published is not None:
            packs.append(published)
    return packs


def _record(
    session: Session, request: PrivacyRequest, decision: Decision, inputs: JurisdictionInputs
) -> None:
    pack = decision.pack
    session.add(
        JurisdictionDecision(
            tenant_id=request.tenant_id,
            request_id=request.id,
            outcome=decision.outcome,
            policy_pack_id=pack.id if pack else None,
            regulation=pack.pack.code if pack else None,
            policy_pack_version=pack.pack.version if pack else None,
            inputs=inputs.as_dict(),
            rationale=decision.rationale,
        )
    )
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR,
        action="jurisdiction.decided",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "outcome": decision.outcome,
            "policy_pack": pack.pack.ref if pack else None,
            "workflow": decision.workflow_code,
            "executable": decision.executable,
        },
    )


def process_verified_case(
    session: Session,
    *,
    request_id: UUID,
    registry: PolicyRegistry,
    keys: KeyProvider,
    cipher: FieldCipher,
) -> CaseStatus | None:
    request = session.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
    ).scalar_one_or_none()
    if request is None or request.status != CaseStatus.VERIFIED:
        return None  # redelivery, or the case moved on: nothing to do

    identifiers = resolution.resolve(session, request=request, keys=keys, cipher=cipher)
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR,
        action="identity.resolved",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "identifiers": len(identifiers),
            "verified": sum(i.assurance == "VERIFIED" for i in identifiers),
            "types": sorted({i.type for i in identifiers}),
        },
    )

    tenant = session.get(Tenant, request.tenant_id)
    right = (
        session.execute(select(RequestRight).where(RequestRight.request_id == request.id))
        .scalars()
        .first()
    )
    challenge = (
        session.execute(
            select(IdentityVerification).where(
                IdentityVerification.request_id == request.id,
                IdentityVerification.status == "VERIFIED",
            )
        )
        .scalars()
        .first()
    )
    assert tenant is not None and right is not None
    inputs = JurisdictionInputs(
        tenant_region=tenant.data_region,
        requester_residency=request.residency_claim,  # type: ignore[arg-type]
        right_code=right.right_code,
        verification_method=challenge.method if challenge else None,
    )
    decision = decide(_candidates(session, registry, request.tenant_id), inputs)
    _record(session, request, decision, inputs)

    if decision.pack is not None:
        request.policy_pack_id = decision.pack.id
        request.workflow_code = decision.workflow_code
        sla = decision.pack.pack.sla.get(right.right_code)  # type: ignore[call-overload]
        # Only a legally validated SLA may set a due date (open decision D-9).
        if sla and sla.validated and sla.response_days and challenge and challenge.verified_at:
            start = challenge.verified_at if sla.clock_start == "VERIFIED" else request.submitted_at
            request.due_at = start + timedelta(days=sla.response_days)
        session.flush()

    event = (
        IntakeEvent.DETERMINE_JURISDICTION if decision.executable else IntakeEvent.ROUTE_TO_MANUAL
    )
    status = transition(session, request, event, actor_type="SYSTEM", actor_ref=ACTOR)
    if status == CaseStatus.JURISDICTION_DETERMINED:
        outbox.enqueue(
            session,
            tenant_id=request.tenant_id,
            topic="case.discovery_requested",
            payload={"request_id": request.id},
        )
    return status
