import uuid
from typing import Any

import pytest

from idprivacy.platform.outbox import Envelope
from idprivacy_worker.celery_app import celery_app
from idprivacy_worker.relay import UnknownTopicError, celery_publisher


def test_celery_is_configured_for_at_least_once_json_only() -> None:
    conf = celery_app.conf
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True
    assert conf.worker_prefetch_multiplier == 1
    assert conf.accept_content == ["json"] and conf.task_serializer == "json"


class _FakeCelery:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any], str]] = []

    def send_task(self, name: str, kwargs: dict[str, Any], task_id: str) -> None:
        self.sent.append((name, kwargs, task_id))


def test_publisher_uses_outbox_id_as_task_id() -> None:
    fake = _FakeCelery()
    env = Envelope(uuid.uuid4(), uuid.uuid4(), "system.noop", {"request_id": str(uuid.uuid4())})
    celery_publisher(fake)(env)
    ((name, kwargs, task_id),) = fake.sent
    assert name == "idprivacy_worker.tasks.noop"
    assert task_id == str(env.id)
    assert kwargs == {"tenant_id": str(env.tenant_id), **env.payload}


def test_publisher_refuses_unknown_topics() -> None:
    env = Envelope(uuid.uuid4(), uuid.uuid4(), "unknown.topic", {})
    with pytest.raises(UnknownTopicError):
        celery_publisher(_FakeCelery())(env)


def test_verified_case_topic_is_routed_to_the_pipeline_task() -> None:
    from idprivacy_worker.tasks import TOPIC_TASKS

    assert TOPIC_TASKS["case.verified"] == "idprivacy_worker.tasks.process_verified_case"
    assert TOPIC_TASKS["case.verified"] in celery_app.tasks


def test_fulfilment_topic_is_routed() -> None:
    from idprivacy_worker.tasks import TOPIC_TASKS

    assert TOPIC_TASKS["case.fulfilment_requested"] in celery_app.tasks


def test_verification_and_evidence_topics_are_routed() -> None:
    from idprivacy_worker.tasks import TOPIC_TASKS

    for topic in ("case.verification_requested", "case.evidence_requested"):
        assert TOPIC_TASKS[topic] in celery_app.tasks


def test_response_topic_is_routed() -> None:
    from idprivacy_worker.tasks import TOPIC_TASKS

    assert TOPIC_TASKS["case.response_requested"] in celery_app.tasks


def test_disclosure_export_topic_is_routed() -> None:
    from idprivacy_worker.tasks import TOPIC_TASKS

    assert TOPIC_TASKS["case.export_requested"] in celery_app.tasks
    assert TOPIC_TASKS["case.report_requested"] in celery_app.tasks
