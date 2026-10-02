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


class _Stop(BaseException):
    """Breaks the relay's endless loop from inside time.sleep."""


def _run_relay(monkeypatch: pytest.MonkeyPatch, results: list[Any]) -> list[float]:
    from idprivacy_worker import relay

    sleeps: list[float] = []
    outcomes = iter(results)

    def fake_relay_once(engine: object, publish: object) -> int:
        r = next(outcomes)
        if isinstance(r, Exception):
            raise r
        return int(r)

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise _Stop

    monkeypatch.setenv("IDP_DATABASE_URL_RELAY", "postgresql://unused")
    monkeypatch.setenv("IDP_RELAY_INTERVAL_SECONDS", "2")
    monkeypatch.setattr(relay, "make_engine", lambda url: "engine")
    monkeypatch.setattr(relay, "configure_logging", lambda: None)
    monkeypatch.setattr(relay, "relay_once", fake_relay_once)
    monkeypatch.setattr(relay.time, "sleep", fake_sleep)
    with pytest.raises(_Stop):
        relay.main()
    return sleeps


def test_relay_keeps_running_after_an_error_and_backs_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # An error (e.g. the broker is down) must not kill the relay; it waits 5x and tries again.
    assert _run_relay(monkeypatch, [RuntimeError("broker down"), 0]) == [10.0, 2.0]


def test_relay_drains_without_sleeping_while_messages_keep_coming(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _run_relay(monkeypatch, [100, 100, 0, 0]) == [2.0, 2.0]
