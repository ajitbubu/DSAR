"""Staff case APIs: list, detail, discovery results (M3).

Every lookup is tenant-scoped by RLS and by the principal's tenant. A case in another
tenant is indistinguishable from a missing one (404, threat model T-08). Reads of a
case's details are audited.
"""

import base64
import unicodedata
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus, InvalidTransition, StaleVersion
from idprivacy.domain.discovery import service as discovery
from idprivacy.domain.identity.resolution import CTX_REQUEST_IDENTIFIER
from idprivacy.domain.policy.model import RetentionDecisionCode
from idprivacy.domain.policy.workflow import GuardFailed, TransitionForbidden, fire
from idprivacy.domain.retention import service as retention
from idprivacy.platform import outbox
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import (
    ConnectorConfig,
    DataMatch,
    DiscoveryJob,
    JurisdictionDecision,
    PolicyPackRow,
    PrivacyRequest,
    RequestIdentifier,
    RequestRight,
    RetentionDecision,
)

router = APIRouter(prefix="/v1/cases", tags=["cases"])
Reader = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_READ))]
Reviewer = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_REVIEW))]
Db = Annotated[Session, Depends(get_tenant_db)]
_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


class CaseSummary(BaseModel):
    id: UUID
    display_id: str
    status: CaseStatus
    rights: list[str]
    submitted_at: datetime
    due_at: datetime | None
    policy_pack: str | None
    workflow: str | None


class CasePage(BaseModel):
    items: list[CaseSummary]
    next_cursor: str | None


class MaskedIdentifier(BaseModel):
    type: str
    masked: str
    assurance: Literal["VERIFIED", "CLAIMED"]


class Jurisdiction(BaseModel):
    outcome: str
    policy_pack: str | None
    rationale: str


class CaseDetail(CaseSummary):
    version: int
    identifiers: list[MaskedIdentifier]
    jurisdiction: Jurisdiction | None


class MatchView(BaseModel):
    id: UUID
    source_record_ref: str
    record_type: str
    data_categories: list[str]
    matched_on: list[str]
    attributes: dict[str, bool | int | str | None]


class SourceView(BaseModel):
    connector_id: str
    display_name: str
    job_status: str
    attempts: int
    error_code: str | None
    finished_at: datetime | None
    matches: list[MatchView]


class DiscoveryView(BaseModel):
    case_status: CaseStatus
    total_matches: int
    sources: list[SourceView]


def mask(kind: str, value: str) -> str:
    if kind == "EMAIL":
        local, _, domain = value.partition("@")
        return f"{local[:1]}•••@{domain[:1]}•••.{domain.rsplit('.', 1)[-1]}"
    if kind == "PHONE":
        return f"{value[:3]}•••••{value[-3:]}"
    return f"{'•' * max(len(value) - 2, 1)}{value[-2:]}"


def _cursor(item: PrivacyRequest) -> str:
    return base64.urlsafe_b64encode(f"{item.submitted_at.isoformat()}|{item.id}".encode()).decode()


def _parse_cursor(raw: str) -> tuple[datetime, UUID]:
    try:
        when, _, ident = base64.urlsafe_b64decode(raw.encode()).decode().partition("|")
        return datetime.fromisoformat(when), UUID(ident)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid cursor") from None


def _summaries(db: Session, cases: list[PrivacyRequest]) -> list[CaseSummary]:
    ids = [c.id for c in cases]
    rights: dict[UUID, list[str]] = {}
    for rid, code in db.execute(
        select(RequestRight.request_id, RequestRight.right_code).where(
            RequestRight.request_id.in_(ids)
        )
    ):
        rights.setdefault(rid, []).append(code)
    packs = {p.id: f"{p.code}@{p.version}" for p in db.execute(select(PolicyPackRow)).scalars()}
    return [
        CaseSummary(
            id=c.id,
            display_id=c.display_id,
            status=CaseStatus(c.status),
            rights=sorted(rights.get(c.id, [])),
            submitted_at=c.submitted_at,
            due_at=c.due_at,
            policy_pack=packs.get(c.policy_pack_id) if c.policy_pack_id else None,
            workflow=c.workflow_code,
        )
        for c in cases
    ]


def _load(db: Session, case_id: UUID) -> PrivacyRequest:
    case = db.get(PrivacyRequest, case_id)
    if case is None:
        raise _NOT_FOUND
    return case


@router.get("", response_model=CasePage)
def list_cases(
    _p: Reader,
    db: Db,
    status_: Annotated[CaseStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> CasePage:
    query = select(PrivacyRequest)
    if status_ is not None:
        query = query.where(PrivacyRequest.status == status_)
    if cursor:
        when, ident = _parse_cursor(cursor)
        query = query.where(
            or_(
                PrivacyRequest.submitted_at < when,
                and_(PrivacyRequest.submitted_at == when, PrivacyRequest.id < ident),
            )
        )
    rows = (
        db.execute(
            query.order_by(PrivacyRequest.submitted_at.desc(), PrivacyRequest.id.desc()).limit(
                limit + 1
            )
        )
        .scalars()
        .all()
    )
    page = list(rows[:limit])
    return CasePage(
        items=_summaries(db, page), next_cursor=_cursor(page[-1]) if len(rows) > limit else None
    )


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: UUID, principal: Reader, db: Db, request: Request) -> CaseDetail:
    case = _load(db, case_id)
    cipher = request.app.state.cipher
    identifiers = [
        MaskedIdentifier(
            type=r.type,
            assurance=r.assurance,
            masked=mask(r.type, cipher.decrypt(r.tenant_id, CTX_REQUEST_IDENTIFIER, r.enc_value)),
        )
        for r in db.execute(
            select(RequestIdentifier)
            .where(RequestIdentifier.request_id == case.id)
            .order_by(RequestIdentifier.type)
        ).scalars()
    ]
    decision = db.execute(
        select(JurisdictionDecision).where(JurisdictionDecision.request_id == case.id)
    ).scalar_one_or_none()
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="case.viewed",
        object_type="privacy_request",
        object_id=case.id,
        details={"view": "detail"},
    )
    (summary,) = _summaries(db, [case])
    return CaseDetail(
        **summary.model_dump(),
        version=case.version,
        identifiers=identifiers,
        jurisdiction=Jurisdiction(
            outcome=decision.outcome,
            policy_pack=(
                f"{decision.regulation}@{decision.policy_pack_version}"
                if decision.regulation
                else None
            ),
            rationale=decision.rationale,
        )
        if decision
        else None,
    )


@router.get("/{case_id}/discovery", response_model=DiscoveryView)
def get_discovery(case_id: UUID, principal: Reader, db: Db) -> DiscoveryView:
    case = _load(db, case_id)
    jobs = db.execute(
        select(DiscoveryJob, ConnectorConfig)
        .join(ConnectorConfig, ConnectorConfig.id == DiscoveryJob.connector_config_id)
        .where(DiscoveryJob.request_id == case.id, DiscoveryJob.purpose == "INITIAL")
        .order_by(ConnectorConfig.connector_id)
    ).all()
    matches: dict[UUID, list[MatchView]] = {}
    for m in db.execute(
        select(DataMatch)
        .where(DataMatch.request_id == case.id)
        .order_by(DataMatch.record_type, DataMatch.source_record_ref)
    ).scalars():
        matches.setdefault(m.discovery_job_id, []).append(
            MatchView(
                id=m.id,
                source_record_ref=m.source_record_ref,
                record_type=m.record_type,
                data_categories=m.data_categories,
                matched_on=m.matched_on,
                attributes=m.attributes,
            )
        )
    sources = [
        SourceView(
            connector_id=cfg.connector_id,
            display_name=cfg.display_name,
            job_status=job.status,
            attempts=job.attempts,
            error_code=job.error_code,
            finished_at=job.finished_at,
            matches=matches.get(job.id, []),
        )
        for job, cfg in jobs
    ]
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="case.viewed",
        object_type="privacy_request",
        object_id=case.id,
        details={"view": "discovery"},
    )
    return DiscoveryView(
        case_status=CaseStatus(case.status),
        total_matches=sum(len(s.matches) for s in sources),
        sources=sources,
    )


@router.post("/{case_id}/discovery/retry", status_code=status.HTTP_202_ACCEPTED)
def retry_discovery(case_id: UUID, principal: Reviewer, db: Db) -> dict[str, int]:
    case = _load(db, case_id)
    if case.status != CaseStatus.DISCOVERY_IN_PROGRESS:
        raise HTTPException(status.HTTP_409_CONFLICT, "Discovery is not in progress")
    reset = discovery.retry_failed(db, request_id=case.id)
    if reset == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "No failed sources to retry")
    outbox.enqueue(
        db,
        tenant_id=case.tenant_id,
        topic="case.discovery_requested",
        payload={"request_id": case.id},
    )
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="discovery.retry_requested",
        object_type="privacy_request",
        object_id=case.id,
        details={"sources": reset},
    )
    return {"sources_reset": reset}


# ---------- Retention review (M4) ------------------------------------------------------


class DecisionView(BaseModel):
    id: UUID
    decision: str
    source: str
    rule_id: str | None
    exception_code: str | None
    exception_reason: str | None
    legal_hold_id: UUID | None
    decided_by: UUID | None
    created_at: datetime


class RetentionItem(BaseModel):
    match_id: UUID
    connector_id: str
    source_record_ref: str
    record_type: str
    data_categories: list[str]
    current: DecisionView | None
    history: list[DecisionView]


class ExceptionCodeView(BaseModel):
    code: str
    label: str
    reference: str | None


class RetentionView(BaseModel):
    case_status: CaseStatus
    case_version: int
    counts: dict[str, int]
    unresolved_manual_review: int
    items: list[RetentionItem]
    exception_codes: list[ExceptionCodeView]
    decisions_allowed: list[str]


def _decision_view(d: RetentionDecision) -> DecisionView:
    return DecisionView(
        id=d.id,
        decision=d.decision,
        source=d.source,
        rule_id=d.rule_id,
        exception_code=d.exception_code,
        exception_reason=d.exception_reason,
        legal_hold_id=d.legal_hold_id,
        decided_by=d.decided_by,
        created_at=d.created_at,
    )


@router.get("/{case_id}/retention", response_model=RetentionView)
def get_retention(case_id: UUID, principal: Reader, db: Db, request: Request) -> RetentionView:
    case = _load(db, case_id)
    current = retention.current_decisions(db, case.id)
    chains = retention.history(db, case.id)
    items = [
        RetentionItem(
            match_id=m.id,
            connector_id=m.connector_id,
            source_record_ref=m.source_record_ref,
            record_type=m.record_type,
            data_categories=m.data_categories,
            current=_decision_view(current[m.id]) if m.id in current else None,
            history=[_decision_view(d) for d in chains.get(m.id, [])],
        )
        for m in db.execute(
            select(DataMatch)
            .where(DataMatch.request_id == case.id)
            .order_by(DataMatch.connector_id, DataMatch.source_record_ref)
        ).scalars()
    ]
    counts: dict[str, int] = {}
    for d in current.values():
        counts[d.decision] = counts.get(d.decision, 0) + 1
    codes: list[ExceptionCodeView] = []
    if case.policy_pack_id:
        pack = request.app.state.services.registry.by_id(db, case.policy_pack_id).pack
        codes = [
            ExceptionCodeView(code=e.code, label=e.label, reference=e.reference)
            for e in pack.exception_codes
        ]
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="case.viewed",
        object_type="privacy_request",
        object_id=case.id,
        details={"view": "retention"},
    )
    return RetentionView(
        case_status=CaseStatus(case.status),
        case_version=case.version,
        counts=counts,
        unresolved_manual_review=counts.get("MANUAL_REVIEW", 0),
        items=items,
        exception_codes=codes,
        decisions_allowed=[d.value for d in RetentionDecisionCode],
    )


class OverrideBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: RetentionDecisionCode
    exception_code: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,31}$")]
    exception_reason: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=10, max_length=2000)
    ]
    expected_current_id: UUID


@router.post(
    "/{case_id}/matches/{match_id}/retention-decisions",
    status_code=status.HTTP_201_CREATED,
    response_model=DecisionView,
)
def override_decision(
    case_id: UUID, match_id: UUID, body: OverrideBody, principal: Reviewer, db: Db, request: Request
) -> DecisionView:
    case = db.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == case_id).with_for_update()
    ).scalar_one_or_none()
    if case is None:
        raise _NOT_FOUND
    if any(
        unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t"
        for ch in body.exception_reason
    ):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unsupported characters")
    try:
        decision = retention.override(
            db,
            request=case,
            match_id=match_id,
            principal=principal,
            data=retention.OverrideInput(
                body.decision, body.exception_code, body.exception_reason, body.expected_current_id
            ),
            registry=request.app.state.services.registry,
        )
    except LookupError:
        raise _NOT_FOUND from None
    except retention.StaleDecision:
        raise HTTPException(status.HTTP_409_CONFLICT, "Decision changed; reload") from None
    except retention.OverrideRejected as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return _decision_view(decision)


class TransitionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,31}$")]
    expected_version: Annotated[int, Field(ge=1)]


class TransitionResult(BaseModel):
    status: CaseStatus
    version: int


@router.post("/{case_id}/transitions", response_model=TransitionResult)
def transition_case(
    case_id: UUID, body: TransitionBody, principal: Reader, db: Db, request: Request
) -> TransitionResult:
    """Fire a user event from the case's pinned workflow. The pack decides who may."""
    case = db.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == case_id).with_for_update()
    ).scalar_one_or_none()
    if case is None:
        raise _NOT_FOUND
    if case.version != body.expected_version:
        raise HTTPException(status.HTTP_409_CONFLICT, "Case changed; reload")
    try:
        new_status = fire(
            db, case, body.event, actor=principal, registry=request.app.state.services.registry
        )
    except TransitionForbidden:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Forbidden") from None
    except GuardFailed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.reason) from None
    except (InvalidTransition, StaleVersion):
        raise HTTPException(status.HTTP_409_CONFLICT, "Transition not allowed now") from None
    return TransitionResult(status=new_status, version=case.version)
