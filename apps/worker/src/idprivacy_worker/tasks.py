"""Task registry. Outbox topics map to Celery task names here."""

from uuid import UUID

import structlog

from idprivacy.domain.discovery import service as discovery
from idprivacy.domain.discovery.connectors import build_connector
from idprivacy.domain.fulfilment import service as fulfilment
from idprivacy.domain.intake.pipeline import process_verified_case as run_pipeline
from idprivacy.domain.retention import service as retention
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from idprivacy.runtime import services
from idprivacy_worker.celery_app import celery_app

log = structlog.get_logger("idprivacy.worker")

TOPIC_TASKS: dict[str, str] = {
    "system.noop": "idprivacy_worker.tasks.noop",
    "case.verified": "idprivacy_worker.tasks.process_verified_case",
    "case.discovery_requested": "idprivacy_worker.tasks.run_discovery",
    "case.fulfilment_requested": "idprivacy_worker.tasks.run_fulfilment",
}


class RetryableConnectorFailure(Exception):
    pass


@celery_app.task(name="idprivacy_worker.tasks.noop")
def noop(tenant_id: str, **ids: str | int) -> None:
    log.info("noop_task_executed", tenant_id=tenant_id, ids=ids)


@celery_app.task(
    name="idprivacy_worker.tasks.process_verified_case",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=5,
)
def process_verified_case(self: object, tenant_id: str, request_id: str) -> None:
    svc = services()
    with tenant_session(svc.engine, TenantContext(UUID(tenant_id))) as session:
        status = run_pipeline(
            session,
            request_id=UUID(request_id),
            registry=svc.registry,
            keys=svc.keys,
            cipher=svc.cipher,
        )
    log.info(
        "verified_case_processed",
        tenant_id=tenant_id,
        request_id=request_id,
        status=status.value if status else "skipped",
    )


@celery_app.task(
    name="idprivacy_worker.tasks.run_discovery",
    bind=True,
    autoretry_for=(RetryableConnectorFailure,),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=6,
)
def run_discovery(self: object, tenant_id: str, request_id: str) -> None:
    svc = services()
    tid, rid = UUID(tenant_id), UUID(request_id)
    with tenant_session(svc.engine, TenantContext(tid)) as session:
        job_ids = discovery.start(session, request_id=rid, registry=svc.registry)
    retryable = False
    for job_id in job_ids:
        outcome = discovery.run_job(
            svc.engine,
            tenant_id=tid,
            job_id=job_id,
            factory=build_connector,
            registry=svc.registry,
            cipher=svc.cipher,
        )
        log.info(
            "discovery_job_finished",
            tenant_id=tenant_id,
            job_id=str(job_id),
            status=outcome.status,
            matches=outcome.matches,
            error_code=outcome.error_code,
        )
        retryable |= outcome.status == "FAILED" and outcome.retryable
    if retryable:
        with tenant_session(svc.engine, TenantContext(tid)) as session:
            discovery.retry_failed(session, request_id=rid)
        raise RetryableConnectorFailure(request_id)
    with tenant_session(svc.engine, TenantContext(tid)) as session:
        # Same transaction: a case can't be left in DISCOVERY_COMPLETE without decisions.
        done = discovery.finish_if_complete(session, request_id=rid, registry=svc.registry)
        if done:
            case = session.get(PrivacyRequest, rid)
            assert case is not None
            retention.evaluate_case(session, request=case, registry=svc.registry)
    log.info("discovery_run_finished", tenant_id=tenant_id, request_id=request_id, complete=done)


@celery_app.task(
    name="idprivacy_worker.tasks.run_fulfilment",
    bind=True,
    autoretry_for=(RetryableConnectorFailure,),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=8,
)
def run_fulfilment(self: object, tenant_id: str, request_id: str) -> None:
    """Dispatch every open task. Safe to redeliver: keys make connector calls idempotent."""
    svc = services()
    tid, rid = UUID(tenant_id), UUID(request_id)
    with tenant_session(svc.engine, TenantContext(tid)) as session:
        task_ids = fulfilment.pending_tasks(session, rid)
    retryable = False
    for task_id in task_ids:
        result = fulfilment.dispatch(
            svc.engine,
            tenant_id=tid,
            task_id=task_id,
            factory=build_connector,
            max_attempts=svc.settings.fulfilment_max_attempts,
        )
        log.info(
            "fulfilment_task_dispatched",
            tenant_id=tenant_id,
            task_id=str(task_id),
            status=result.status,
        )
        retryable |= result.retryable or result.status == "BUSY"
    if retryable:
        raise RetryableConnectorFailure(request_id)
    with tenant_session(svc.engine, TenantContext(tid)) as session:
        done = fulfilment.finish_if_complete(session, request_id=rid, registry=svc.registry)
    log.info("fulfilment_run_finished", tenant_id=tenant_id, request_id=request_id, complete=done)
