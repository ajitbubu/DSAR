"""Maker-checker approval endpoints (M5; screen 8)."""

import re
import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from idprivacy.domain.approvals import service as approvals
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.policy.workflow import GuardFailed, TransitionForbidden, fire
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import Approval, PrivacyRequest

router = APIRouter(prefix="/v1", tags=["approvals"])
Approver = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_APPROVE))]
Reader = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_READ))]
Db = Annotated[Session, Depends(get_tenant_db)]
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["APPROVED", "REJECTED"]
    case_version: Annotated[int, Field(ge=1)]
    decision_set_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    comment: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] | None = None


class ApprovalView(BaseModel):
    id: UUID
    outcome: str
    case_version: int
    decision_set_sha256: str
    submitted_by: UUID
    approved_by: UUID
    comment: str | None
    created_at: datetime


class QueueItem(BaseModel):
    id: UUID
    display_id: str
    submitted_at: datetime
    submitted_by: UUID
    case_version: int
    decision_set_sha256: str
    you_submitted: bool


def _view(a: Approval) -> ApprovalView:
    return ApprovalView(
        id=a.id,
        outcome=a.outcome,
        case_version=a.case_version,
        decision_set_sha256=a.decision_set_sha256,
        submitted_by=a.submitted_by,
        approved_by=a.approved_by,
        comment=a.comment,
        created_at=a.created_at,
    )


@router.get("/approvals/queue", response_model=list[QueueItem])
def approval_queue(principal: Approver, db: Db) -> list[QueueItem]:
    items = []
    cases = db.execute(
        select(PrivacyRequest)
        .where(PrivacyRequest.status == CaseStatus.PENDING_APPROVAL)
        .order_by(PrivacyRequest.submitted_at)
    ).scalars()
    for case in cases:
        sub = approvals.latest_submission(db, case.id)
        if sub is None:
            continue
        items.append(
            QueueItem(
                id=case.id,
                display_id=case.display_id,
                submitted_at=sub.created_at,
                submitted_by=sub.submitted_by,
                case_version=sub.case_version,
                decision_set_sha256=sub.decision_set_sha256,
                you_submitted=sub.submitted_by == principal.user_id,
            )
        )
    return items


@router.get("/cases/{case_id}/approvals", response_model=list[ApprovalView])
def approval_history(case_id: UUID, _p: Reader, db: Db) -> list[ApprovalView]:
    if db.get(PrivacyRequest, case_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    rows = db.execute(
        select(Approval).where(Approval.request_id == case_id).order_by(Approval.created_at)
    ).scalars()
    return [_view(a) for a in rows]


@router.post(
    "/cases/{case_id}/approvals", status_code=status.HTTP_201_CREATED, response_model=ApprovalView
)
def decide(
    case_id: UUID,
    body: ApprovalBody,
    principal: Approver,
    db: Db,
    request: Request,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> Any:
    if not KEY_RE.fullmatch(idempotency_key):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid Idempotency-Key")
    if body.outcome == "REJECTED" and (not body.comment or len(body.comment) < 10):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "A rejection needs a comment of at least 10 characters",
        )
    if body.comment and any(
        unicodedata.category(c) in {"Cc", "Cf"} and c not in "\n\t" for c in body.comment
    ):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unsupported characters")

    case = db.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == case_id).with_for_update()
    ).scalar_one_or_none()
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    try:
        prior = approvals.replay(db, request_id=case.id, key=idempotency_key, outcome=body.outcome)
        if prior is not None:
            return JSONResponse(prior, status_code=status.HTTP_201_CREATED)
        data = approvals.ApprovalInput(
            body.outcome, body.case_version, body.decision_set_sha256, body.comment, idempotency_key
        )
        submission = approvals.check(db, request=case, principal=principal, data=data)
    except approvals.ApprovalForbidden as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
    except approvals.ApprovalConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None

    approval_id, now = uuid4(), datetime.now(UTC)
    response = ApprovalView(
        id=approval_id,
        outcome=body.outcome,
        case_version=body.case_version,
        decision_set_sha256=body.decision_set_sha256,
        submitted_by=submission.submitted_by,
        approved_by=principal.user_id,
        comment=body.comment,
        created_at=now,
    ).model_dump(mode="json")
    try:
        with db.begin_nested():
            approvals.record(
                db,
                request=case,
                principal=principal,
                submission=submission,
                data=data,
                approval_id=approval_id,
                created_at=now,
                response=response,
            )
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Already decided") from None
    event = "APPROVE" if body.outcome == "APPROVED" else "REJECT"
    try:
        fire(db, case, event, actor=principal, registry=request.app.state.services.registry)
    except TransitionForbidden:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden") from None
    except GuardFailed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.reason) from None
    return JSONResponse(response, status_code=status.HTTP_201_CREATED)
