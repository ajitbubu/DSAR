"""Case status model and intake transitions.

These intake transitions (submit → verify → verified, cancel) hold for every regulation.
Rights-specific workflows after VERIFIED are loaded from policy packs in M2 (ADR-0005).
Handlers never assign ``status`` directly; they call ``transition``.
"""

from enum import StrEnum

from sqlalchemy import update
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.audit.service import ActorType
from idprivacy.platform.models import PrivacyRequest


class CaseStatus(StrEnum):
    SUBMITTED = "SUBMITTED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFIED = "VERIFIED"
    JURISDICTION_DETERMINED = "JURISDICTION_DETERMINED"
    DISCOVERY_IN_PROGRESS = "DISCOVERY_IN_PROGRESS"
    DISCOVERY_COMPLETE = "DISCOVERY_COMPLETE"
    RETENTION_EVALUATED = "RETENTION_EVALUATED"
    UNDER_REVIEW = "UNDER_REVIEW"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    FULFILMENT_IN_PROGRESS = "FULFILMENT_IN_PROGRESS"
    VERIFICATION_IN_PROGRESS = "VERIFICATION_IN_PROGRESS"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    VERIFIED_COMPLETE = "VERIFIED_COMPLETE"
    EVIDENCE_GENERATED = "EVIDENCE_GENERATED"
    RESPONDED = "RESPONDED"
    CLOSED = "CLOSED"
    ON_HOLD = "ON_HOLD"
    CANCELLED = "CANCELLED"
    PENDING_MANUAL_HANDLING = "PENDING_MANUAL_HANDLING"


TERMINAL = frozenset({CaseStatus.CLOSED, CaseStatus.CANCELLED, CaseStatus.VERIFICATION_FAILED})

# The requester may withdraw only before any destructive work is authorised.
CANCELLABLE = frozenset(
    {
        CaseStatus.SUBMITTED,
        CaseStatus.PENDING_VERIFICATION,
        CaseStatus.VERIFIED,
        CaseStatus.JURISDICTION_DETERMINED,
        CaseStatus.DISCOVERY_IN_PROGRESS,
        CaseStatus.DISCOVERY_COMPLETE,
        CaseStatus.RETENTION_EVALUATED,
        CaseStatus.UNDER_REVIEW,
        CaseStatus.PENDING_APPROVAL,
        CaseStatus.REJECTED,
        CaseStatus.PENDING_MANUAL_HANDLING,
    }
)


class IntakeEvent(StrEnum):
    ISSUE_CHALLENGE = "ISSUE_CHALLENGE"
    VERIFY = "VERIFY"
    FAIL_VERIFICATION = "FAIL_VERIFICATION"
    DETERMINE_JURISDICTION = "DETERMINE_JURISDICTION"
    ROUTE_TO_MANUAL = "ROUTE_TO_MANUAL"
    CANCEL = "CANCEL"


_TRANSITIONS: dict[tuple[CaseStatus, IntakeEvent], CaseStatus] = {
    (CaseStatus.SUBMITTED, IntakeEvent.ISSUE_CHALLENGE): CaseStatus.PENDING_VERIFICATION,
    (CaseStatus.PENDING_VERIFICATION, IntakeEvent.VERIFY): CaseStatus.VERIFIED,
    (
        CaseStatus.PENDING_VERIFICATION,
        IntakeEvent.FAIL_VERIFICATION,
    ): CaseStatus.VERIFICATION_FAILED,
    # Hand-off to the pinned policy pack's workflow (or to manual handling).
    (CaseStatus.VERIFIED, IntakeEvent.DETERMINE_JURISDICTION): CaseStatus.JURISDICTION_DETERMINED,
    (CaseStatus.VERIFIED, IntakeEvent.ROUTE_TO_MANUAL): CaseStatus.PENDING_MANUAL_HANDLING,
    **{(s, IntakeEvent.CANCEL): CaseStatus.CANCELLED for s in CANCELLABLE},
}


class InvalidTransition(Exception):
    pass


class StaleVersion(Exception):
    pass


def transition(
    session: Session,
    request: PrivacyRequest,
    event: IntakeEvent,
    *,
    actor_type: ActorType,
    actor_ref: str,
) -> CaseStatus:
    current = CaseStatus(request.status)
    target = _TRANSITIONS.get((current, event))
    if target is None:
        raise InvalidTransition(f"{event} not allowed from {current}")
    apply_status(
        session,
        request,
        event=event.value,
        target=target,
        actor_type=actor_type,
        actor_ref=actor_ref,
    )
    return target


def apply_status(
    session: Session,
    request: PrivacyRequest,
    *,
    event: str,
    target: CaseStatus,
    actor_type: ActorType,
    actor_ref: str,
    details: dict[str, str] | None = None,
) -> None:
    """Persist a validated transition: optimistic-lock the row, bump version, audit it."""
    current = CaseStatus(request.status)
    result = session.execute(
        update(PrivacyRequest)
        .where(PrivacyRequest.id == request.id, PrivacyRequest.version == request.version)
        .values(status=target, version=request.version + 1)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise StaleVersion(str(request.id))
    session.refresh(request)
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type=actor_type,
        actor_ref=actor_ref,
        action="case.transitioned",
        object_type="privacy_request",
        object_id=request.id,
        details={"event": event, "from": current.value, "to": target.value, **(details or {})},
    )
