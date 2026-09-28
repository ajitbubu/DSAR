"""Fulfilment execution view and manual retry (M6; screen 9)."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.fulfilment import service as fulfilment
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import (
    ConnectorConfig,
    ConnectorExecution,
    DataMatch,
    FulfilmentTask,
    PrivacyRequest,
)

router = APIRouter(prefix="/v1/cases", tags=["fulfilment"])
Reader = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_READ))]
Reviewer = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_REVIEW))]
Db = Annotated[Session, Depends(get_tenant_db)]


class ExecutionView(BaseModel):
    operation: str
    attempt_no: int
    outcome: str
    error_code: str | None
    receipt_id: str | None
    replayed: bool | None
    evidence_sha256: str | None
    finished_at: datetime


class TaskView(BaseModel):
    id: UUID
    source_record_ref: str
    connector_id: str
    action: str
    status: str
    attempt_count: int
    skip_reason: str | None
    receipt_id: str | None
    outcome: str | None
    last_error_code: str | None
    executions: list[ExecutionView]


class FulfilmentView(BaseModel):
    case_status: CaseStatus
    counts: dict[str, int]
    tasks: list[TaskView]


@router.get("/{case_id}/fulfilment-tasks", response_model=FulfilmentView)
def list_tasks(case_id: UUID, _p: Reader, db: Db) -> FulfilmentView:
    case = db.get(PrivacyRequest, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    executions: dict[UUID, list[ExecutionView]] = {}
    for e in db.execute(
        select(ConnectorExecution)
        .join(FulfilmentTask, FulfilmentTask.id == ConnectorExecution.fulfilment_task_id)
        .where(FulfilmentTask.request_id == case.id)
        .order_by(ConnectorExecution.started_at)
    ).scalars():
        executions.setdefault(e.fulfilment_task_id, []).append(
            ExecutionView(
                operation=e.operation,
                attempt_no=e.attempt_no,
                outcome=e.outcome,
                error_code=e.error_code,
                receipt_id=e.receipt_id,
                replayed=e.replayed,
                evidence_sha256=e.evidence_sha256,
                finished_at=e.finished_at,
            )
        )
    rows = db.execute(
        select(FulfilmentTask, DataMatch, ConnectorConfig)
        .join(DataMatch, DataMatch.id == FulfilmentTask.data_match_id)
        .join(ConnectorConfig, ConnectorConfig.id == FulfilmentTask.connector_config_id)
        .where(FulfilmentTask.request_id == case.id)
        .order_by(ConnectorConfig.connector_id, DataMatch.source_record_ref)
    ).all()
    tasks = [
        TaskView(
            id=t.id,
            source_record_ref=m.source_record_ref,
            connector_id=c.connector_id,
            action=t.action,
            status=t.status,
            attempt_count=t.attempt_count,
            skip_reason=t.skip_reason,
            receipt_id=t.receipt_id,
            outcome=t.outcome,
            last_error_code=t.last_error_code,
            executions=executions.get(t.id, []),
        )
        for t, m, c in rows
    ]
    counts: dict[str, int] = {}
    for t in tasks:
        counts[t.status] = counts.get(t.status, 0) + 1
    return FulfilmentView(case_status=CaseStatus(case.status), counts=counts, tasks=tasks)


@router.post("/{case_id}/fulfilment-tasks/{task_id}/retry", status_code=status.HTTP_202_ACCEPTED)
def retry_task(case_id: UUID, task_id: UUID, principal: Reviewer, db: Db) -> dict[str, str]:
    case = db.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == case_id).with_for_update()
    ).scalar_one_or_none()
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    try:
        fulfilment.retry_task(
            db, request=case, task_id=task_id, principal_ref=str(principal.user_id)
        )
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found") from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return {"status": "PENDING"}
