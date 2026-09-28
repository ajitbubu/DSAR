"""Task registry. Outbox topics map to Celery task names here."""

from uuid import UUID

import structlog

from idprivacy.domain.intake.pipeline import process_verified_case as run_pipeline
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.runtime import services
from idprivacy_worker.celery_app import celery_app

log = structlog.get_logger("idprivacy.worker")

TOPIC_TASKS: dict[str, str] = {
    "system.noop": "idprivacy_worker.tasks.noop",
    "case.verified": "idprivacy_worker.tasks.process_verified_case",
}


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
