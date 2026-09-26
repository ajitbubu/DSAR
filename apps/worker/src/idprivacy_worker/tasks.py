"""Task registry. Outbox topics map to Celery task names here; later milestones add topics."""

import structlog

from idprivacy_worker.celery_app import celery_app

log = structlog.get_logger("idprivacy.worker")

TOPIC_TASKS: dict[str, str] = {
    "system.noop": "idprivacy_worker.tasks.noop",
}


@celery_app.task(name="idprivacy_worker.tasks.noop")
def noop(tenant_id: str, **ids: str | int) -> None:
    log.info("noop_task_executed", tenant_id=tenant_id, ids=ids)
