"""Outbox relay process: publishes committed outbox rows to Celery (ADR-0005)."""

import os
import time

import structlog
from celery import Celery

from idprivacy.platform.db import make_engine
from idprivacy.platform.logging import configure_logging
from idprivacy.platform.outbox import Envelope, relay_once
from idprivacy_worker.tasks import TOPIC_TASKS

log = structlog.get_logger("idprivacy.relay")


class UnknownTopicError(LookupError):
    pass


def celery_publisher(app: Celery):  # type: ignore[no-untyped-def]
    def publish(env: Envelope) -> None:
        task_name = TOPIC_TASKS.get(env.topic)
        if task_name is None:
            raise UnknownTopicError(env.topic)
        # task_id = outbox id, so consumers can deduplicate redeliveries.
        app.send_task(
            task_name, kwargs={"tenant_id": str(env.tenant_id), **env.payload}, task_id=str(env.id)
        )

    return publish


def main() -> None:
    from idprivacy_worker.celery_app import celery_app

    configure_logging()
    engine = make_engine(os.environ["IDP_DATABASE_URL_RELAY"])
    publish = celery_publisher(celery_app)
    interval = float(os.environ.get("IDP_RELAY_INTERVAL_SECONDS", "1"))
    log.info("outbox_relay_started")
    while True:
        try:
            if relay_once(engine, publish) == 0:
                time.sleep(interval)
        except Exception:
            log.exception("outbox_relay_error")
            time.sleep(interval * 5)


if __name__ == "__main__":
    main()
