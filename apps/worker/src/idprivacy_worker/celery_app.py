"""Celery application. Task payloads carry identifiers only (see idprivacy.platform.outbox)."""

import os

from celery import Celery
from celery.signals import setup_logging

from idprivacy.platform.logging import configure_logging

celery_app = Celery(
    "idprivacy",
    broker=os.environ.get("IDP_REDIS_URL", "redis://redis:6379/0"),
    include=["idprivacy_worker.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_ignore_result=True,
    broker_connection_retry_on_startup=True,
    worker_hijack_root_logger=False,
)


@setup_logging.connect
def _configure_logging(**_: object) -> None:
    configure_logging()
