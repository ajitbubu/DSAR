"""Fulfilment orchestration (M6; ADR-0006, threat model T-12).

Destructive calls are safe under retries, redelivery and worker crashes:
- each task has a deterministic idempotency key (tenant, task, action, decision),
- the task is committed as DISPATCHED *before* the connector is called,
- the connector is called outside any DB transaction, with the same key on every attempt,
- every completed call is recorded append-only in connector_execution.
Legal holds are re-checked immediately before dispatch.
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from idprivacy_connector_sdk import (
    Action,
    ActionRequest,
    ConnectorError,
    EvidenceRequest,
    idempotency_key,
)
from sqlalchemy import Engine, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.discovery.service import ConnectorFactory
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.domain.retention.service import active_hold_for, current_decisions
from idprivacy.platform import outbox
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    Approval,
    ConnectorConfig,
    ConnectorExecution,
    DataMatch,
    DiscoveryJob,
    FulfilmentTask,
    PrivacyRequest,
)

ACTOR = SystemActor("system:fulfilment")
TERMINAL = frozenset({"SUCCEEDED", "FAILED_FINAL", "SKIPPED", "CANCELLED"})
DESTRUCTIVE = {"DELETE": Action.DELETE, "ANONYMIZE": Action.ANONYMIZE, "RESTRICT": Action.RESTRICT}


def plan(
    session: Session, *, request: PrivacyRequest, approval: Approval, registry: PolicyRegistry
) -> int:
    """Create one task per current decision and start fulfilment. Idempotent per approval."""
    decisions = current_decisions(session, request.id)
    created = 0
    for match_id, decision in sorted(decisions.items(), key=lambda kv: str(kv[0])):
        exists = session.execute(
            select(FulfilmentTask.id).where(
                FulfilmentTask.data_match_id == match_id, FulfilmentTask.approval_id == approval.id
            )
        ).first()
        if exists:
            continue
        match = session.get(DataMatch, match_id)
        assert match is not None
        job = session.get(DiscoveryJob, match.discovery_job_id)
        assert job is not None
        task_id = uuid.uuid4()
        destructive = decision.decision in DESTRUCTIVE
        session.add(
            FulfilmentTask(
                id=task_id,
                tenant_id=request.tenant_id,
                request_id=request.id,
                data_match_id=match_id,
                retention_decision_id=decision.id,
                approval_id=approval.id,
                connector_config_id=job.connector_config_id,
                action=decision.decision if destructive else "NOOP_RETAIN",
                idempotency_key=idempotency_key(
                    request.tenant_id, task_id, decision.decision, decision.id
                ),
                status="PENDING" if destructive else "SKIPPED",
                attempt_count=0,
                skip_reason=None
                if destructive
                else f"{decision.decision}: {decision.exception_code or 'no action required'}",
            )
        )
        created += 1
    session.flush()
    fire(session, request, "START_FULFILMENT", actor=ACTOR, registry=registry)
    outbox.enqueue(
        session,
        tenant_id=request.tenant_id,
        topic="case.fulfilment_requested",
        payload={"request_id": request.id},
    )
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR.ref,
        action="fulfilment.planned",
        object_type="privacy_request",
        object_id=request.id,
        details={"tasks": created, "approval_id": str(approval.id)},
    )
    return created


@dataclass(frozen=True)
class DispatchResult:
    status: str
    retryable: bool = False


def _now() -> datetime:
    return datetime.now(UTC)


def dispatch(
    engine: Engine, *, tenant_id: UUID, task_id: UUID, factory: ConnectorFactory, max_attempts: int
) -> DispatchResult:
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        task = s.execute(
            select(FulfilmentTask)
            .where(FulfilmentTask.id == task_id)
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if task is None:
            return DispatchResult("BUSY")
        if task.status in TERMINAL:
            return DispatchResult(task.status)
        request = s.get(PrivacyRequest, task.request_id)
        match = s.get(DataMatch, task.data_match_id)
        config = s.get(ConnectorConfig, task.connector_config_id)
        assert request is not None and match is not None and config is not None
        hold = active_hold_for(s, request=request, match=match)
        if hold is not None:
            task.status, task.skip_reason = "SKIPPED", f"LEGAL_HOLD: {hold.matter_ref}"
            task.updated_at = _now()
            audit.append(
                s,
                tenant_id=tenant_id,
                actor_type="SYSTEM",
                actor_ref=ACTOR.ref,
                action="fulfilment.skipped_for_hold",
                object_type="fulfilment_task",
                object_id=task.id,
                details={"legal_hold_id": str(hold.id)},
            )
            return DispatchResult("SKIPPED")
        task.status, task.attempt_count = "DISPATCHED", task.attempt_count + 1
        task.updated_at = _now()
        attempt, key, action = task.attempt_count, task.idempotency_key, DESTRUCTIVE[task.action]
        ref, connector_id = match.source_record_ref, config.connector_id
        connector = factory(config)
    # Committed as DISPATCHED. A crash from here on leaves the task resumable with the same key.

    started = _now()
    try:
        result = connector.execute_action(
            ActionRequest(idempotency_key=key, action=action, source_record_ref=ref)
        )
    except ConnectorError as exc:
        final = not exc.retryable or attempt >= max_attempts
        with tenant_session(engine, ctx) as s:
            task = s.get(FulfilmentTask, task_id)
            assert task is not None
            task.status = "FAILED_FINAL" if final else "FAILED_RETRYABLE"
            task.last_error_code, task.updated_at = exc.code, _now()
            s.add(
                ConnectorExecution(
                    tenant_id=tenant_id,
                    fulfilment_task_id=task_id,
                    idempotency_key=key,
                    operation="execute_action",
                    attempt_no=attempt,
                    outcome=task.status,
                    error_code=exc.code,
                    started_at=started,
                    finished_at=_now(),
                )
            )
            audit.append(
                s,
                tenant_id=tenant_id,
                actor_type="CONNECTOR",
                actor_ref=f"connector:{connector_id}",
                action="fulfilment.attempt_failed",
                object_type="fulfilment_task",
                object_id=task_id,
                details={"attempt": attempt, "error_code": exc.code, "final": final},
            )
        return DispatchResult(task.status, retryable=not final)

    with tenant_session(engine, ctx) as s:
        task = s.get(FulfilmentTask, task_id)
        assert task is not None
        task.status, task.receipt_id, task.outcome = "SUCCEEDED", result.receipt_id, result.outcome
        task.last_error_code, task.updated_at = None, _now()
        s.add(
            ConnectorExecution(
                tenant_id=tenant_id,
                fulfilment_task_id=task_id,
                idempotency_key=key,
                operation="execute_action",
                attempt_no=attempt,
                outcome="SUCCEEDED",
                receipt_id=result.receipt_id,
                replayed=result.replayed,
                started_at=started,
                finished_at=_now(),
            )
        )
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="CONNECTOR",
            actor_ref=f"connector:{connector_id}",
            action="fulfilment.action_applied",
            object_type="fulfilment_task",
            object_id=task_id,
            details={
                "action": action.value,
                "outcome": result.outcome,
                "replayed": result.replayed,
                "attempt": attempt,
                "receipt_id": result.receipt_id,
            },
        )
    capture_evidence(engine, tenant_id=tenant_id, task_id=task_id, factory=factory)
    return DispatchResult("SUCCEEDED")


def capture_evidence(
    engine: Engine, *, tenant_id: UUID, task_id: UUID, factory: ConnectorFactory
) -> bool:
    """Fetch the connector's evidence for a succeeded task. Safe to call repeatedly."""
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        task = s.get(FulfilmentTask, task_id)
        assert task is not None
        if task.status != "SUCCEEDED" or task.receipt_id is None:
            return False
        done = s.execute(
            select(ConnectorExecution.id).where(
                ConnectorExecution.fulfilment_task_id == task_id,
                ConnectorExecution.operation == "get_evidence",
                ConnectorExecution.outcome == "SUCCEEDED",
            )
        ).first()
        if done:
            return True
        attempt = 1 + (
            s.execute(
                select(func.count()).where(
                    ConnectorExecution.fulfilment_task_id == task_id,
                    ConnectorExecution.operation == "get_evidence",
                )
            ).scalar_one()
        )
        config = s.get(ConnectorConfig, task.connector_config_id)
        assert config is not None
        connector, receipt, key = factory(config), task.receipt_id, task.idempotency_key
    started = _now()
    try:
        bundle = connector.get_evidence(EvidenceRequest(receipt_id=receipt))
        body = bundle.model_dump(mode="json")
        digest = hashlib.sha256(bundle.model_dump_json().encode()).hexdigest()
        outcome, error = "SUCCEEDED", None
    except ConnectorError as exc:
        body, digest, outcome, error = (
            None,
            None,
            ("FAILED_RETRYABLE" if exc.retryable else "FAILED_FINAL"),
            exc.code,
        )
    with tenant_session(engine, ctx) as s:
        # Concurrent dispatchers may both capture evidence for the same attempt number;
        # the duplicate is harmless, so the insert is idempotent.
        s.execute(
            pg_insert(ConnectorExecution)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                fulfilment_task_id=task_id,
                idempotency_key=key,
                operation="get_evidence",
                attempt_no=attempt,
                outcome=outcome,
                error_code=error,
                receipt_id=receipt,
                evidence=body,
                evidence_sha256=digest,
                started_at=started,
                finished_at=_now(),
            )
            .on_conflict_do_nothing(constraint="uq_connector_execution_attempt")
        )
    return outcome == "SUCCEEDED"


def pending_tasks(session: Session, request_id: UUID) -> list[UUID]:
    return list(
        session.execute(
            select(FulfilmentTask.id)
            .where(FulfilmentTask.request_id == request_id, FulfilmentTask.status.notin_(TERMINAL))
            .order_by(FulfilmentTask.id)
        ).scalars()
    )


def all_terminal(session: Session, request_id: UUID) -> tuple[bool, int]:
    open_ = session.execute(
        select(func.count()).where(
            FulfilmentTask.request_id == request_id, FulfilmentTask.status.notin_(TERMINAL)
        )
    ).scalar_one()
    return open_ == 0, int(open_)


def finish_if_complete(session: Session, *, request_id: UUID, registry: PolicyRegistry) -> bool:
    request = session.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
    ).scalar_one_or_none()
    if request is None or request.status != CaseStatus.FULFILMENT_IN_PROGRESS:
        return False
    if not all_terminal(session, request_id)[0]:
        return False
    fire(session, request, "START_VERIFICATION", actor=ACTOR, registry=registry)
    outbox.enqueue(
        session,
        tenant_id=request.tenant_id,
        topic="case.verification_requested",
        payload={"request_id": request.id},
    )
    return True


def retry_task(
    session: Session, *, request: PrivacyRequest, task_id: UUID, principal_ref: str
) -> None:
    """Re-open a FAILED_FINAL task. It keeps its idempotency key."""
    if request.status != CaseStatus.FULFILMENT_IN_PROGRESS:
        raise ValueError("fulfilment is not in progress")
    task = session.execute(
        select(FulfilmentTask)
        .where(FulfilmentTask.id == task_id, FulfilmentTask.request_id == request.id)
        .with_for_update()
    ).scalar_one_or_none()
    if task is None:
        raise LookupError(task_id)
    if task.status != "FAILED_FINAL":
        raise ValueError("only permanently failed tasks can be retried")
    task.status, task.updated_at = "PENDING", _now()
    outbox.enqueue(
        session,
        tenant_id=request.tenant_id,
        topic="case.fulfilment_requested",
        payload={"request_id": request.id},
    )
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=principal_ref,
        action="fulfilment.retry_requested",
        object_type="fulfilment_task",
        object_id=task.id,
        details={"attempts_so_far": task.attempt_count},
    )
