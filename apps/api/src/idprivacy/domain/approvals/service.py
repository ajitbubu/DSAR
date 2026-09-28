"""Maker-checker approval (M5; threat model T-11).

An approval is bound to (case version, decision-set hash) from the latest submission.
Any change to the decisions, or any other case transition, invalidates it. The approver
must differ from the submitter and must not have authored any override in the set.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.retention.service import current_decisions
from idprivacy.platform.auth.rbac import StaffPrincipal
from idprivacy.platform.models import Approval, ApprovalSubmission, PrivacyRequest


class ApprovalConflict(Exception):
    """409: the case or its decisions changed, or the key was reused."""


class ApprovalForbidden(Exception):
    """403: maker-checker separation would be violated."""


def decision_set_hash(session: Session, request_id: UUID) -> str:
    items = sorted(
        (str(match_id), str(d.id), d.decision, d.exception_code or "")
        for match_id, d in current_decisions(session, request_id).items()
    )
    body = json.dumps({"request_id": str(request_id), "decisions": items}, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def latest_submission(session: Session, request_id: UUID) -> ApprovalSubmission | None:
    return session.execute(
        select(ApprovalSubmission)
        .where(ApprovalSubmission.request_id == request_id)
        .order_by(ApprovalSubmission.created_at.desc(), ApprovalSubmission.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def record_submission(
    session: Session, *, request: PrivacyRequest, principal: StaffPrincipal
) -> ApprovalSubmission:
    """Called when a case enters PENDING_APPROVAL."""
    submission = ApprovalSubmission(
        tenant_id=request.tenant_id,
        request_id=request.id,
        submitted_by=principal.user_id,
        case_version=request.version,
        decision_set_sha256=decision_set_hash(session, request.id),
    )
    session.add(submission)
    session.flush()
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="approval.submitted",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "case_version": request.version,
            "decision_set_sha256": submission.decision_set_sha256,
        },
    )
    return submission


def override_authors(session: Session, request_id: UUID) -> set[UUID]:
    return {
        d.decided_by
        for d in current_decisions(session, request_id).values()
        if d.source == "ANALYST_OVERRIDE" and d.decided_by is not None
    }


@dataclass(frozen=True)
class ApprovalInput:
    outcome: Literal["APPROVED", "REJECTED"]
    case_version: int
    decision_set_sha256: str
    comment: str | None
    idempotency_key: str


def replay(session: Session, *, request_id: UUID, key: str, outcome: str) -> dict[str, Any] | None:
    prior = session.execute(
        select(Approval).where(Approval.idempotency_key == key)
    ).scalar_one_or_none()
    if prior is None:
        return None
    if prior.request_id != request_id or prior.outcome != outcome:
        raise ApprovalConflict("Idempotency-Key was already used for a different decision")
    return prior.response


def check(
    session: Session, *, request: PrivacyRequest, principal: StaffPrincipal, data: ApprovalInput
) -> ApprovalSubmission:
    """Validate an approval attempt. Raises ApprovalConflict / ApprovalForbidden."""
    if request.status != CaseStatus.PENDING_APPROVAL:
        raise ApprovalConflict("case is not awaiting approval")
    if request.version != data.case_version:
        raise ApprovalConflict("case changed since you reviewed it; reload")
    submission = latest_submission(session, request.id)
    current = decision_set_hash(session, request.id)
    if (
        submission is None
        or submission.decision_set_sha256 != current
        or data.decision_set_sha256 != current
    ):
        raise ApprovalConflict("decisions changed since you reviewed them; reload")
    if principal.user_id == submission.submitted_by:
        raise ApprovalForbidden("you submitted this case, so a different approver must decide")
    if principal.user_id in override_authors(session, request.id):
        raise ApprovalForbidden("you changed decisions in this set, so you can't approve it")
    return submission


def record(
    session: Session,
    *,
    request: PrivacyRequest,
    principal: StaffPrincipal,
    submission: ApprovalSubmission,
    data: ApprovalInput,
    approval_id: UUID,
    created_at: datetime,
    response: dict[str, Any],
) -> Approval:
    """Insert the (append-only) approval, including the response replayed for its key."""
    approval = Approval(
        id=approval_id,
        created_at=created_at,
        tenant_id=request.tenant_id,
        request_id=request.id,
        submission_id=submission.id,
        case_version=data.case_version,
        decision_set_sha256=data.decision_set_sha256,
        submitted_by=submission.submitted_by,
        approved_by=principal.user_id,
        outcome=data.outcome,
        comment=data.comment,
        idempotency_key=data.idempotency_key,
        response=response,
    )
    session.add(approval)
    session.flush()
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action=f"approval.{data.outcome.lower()}",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "case_version": data.case_version,
            "decision_set_sha256": data.decision_set_sha256,
            "submitted_by": str(submission.submitted_by),
            "has_comment": bool(data.comment),
        },
    )
    return approval


def latest_approval_is_valid(session: Session, request: PrivacyRequest) -> tuple[bool, str]:
    """Second enforcement point, used by the pack guard ``approval_valid_for_version``."""
    approval = session.execute(
        select(Approval)
        .where(Approval.request_id == request.id)
        .order_by(Approval.created_at.desc(), Approval.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    submission = latest_submission(session, request.id)
    if approval is None or submission is None or approval.submission_id != submission.id:
        return False, "no approval for the current submission"
    if approval.outcome != "APPROVED":
        return False, "latest decision was not an approval"
    if approval.case_version != request.version:
        return False, "approval is for a different case version"
    if approval.decision_set_sha256 != decision_set_hash(session, request.id):
        return False, "decisions changed after approval"
    if approval.approved_by == approval.submitted_by:
        return False, "maker and checker are the same person"
    return True, ""
