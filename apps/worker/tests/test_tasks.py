"""Task wrappers: retry decisions and wiring, with the domain services faked.

The domain behaviour behind each task (idempotency, state transitions) is covered by the
API suite against Postgres. These tests pin what only the worker decides: when a task
asks Celery to retry, and that a redelivered message is harmless at this layer.
"""

import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from idprivacy_worker import tasks

TID, RID = str(uuid.uuid4()), str(uuid.uuid4())


@dataclass
class Calls:
    log: list[tuple[str, Any]] = field(default_factory=list)

    def names(self) -> list[str]:
        return [name for name, _ in self.log]


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    """Fake services() and tenant_session() so no task touches a database."""
    c = Calls()
    svc = SimpleNamespace(
        engine="engine",
        registry="registry",
        keys="keys",
        cipher="cipher",
        blob_store="store",
        settings=SimpleNamespace(fulfilment_max_attempts=3, discovery_max_attempts=4),
    )
    monkeypatch.setattr(tasks, "services", lambda: svc)

    @contextmanager
    def fake_session(engine: object, ctx: Any):  # type: ignore[no-untyped-def]
        c.log.append(("session", str(ctx.tenant_id)))
        yield "session"

    monkeypatch.setattr(tasks, "tenant_session", fake_session)
    return c


def outcome(**kw: Any) -> SimpleNamespace:
    base = {"status": "SUCCEEDED", "retryable": False, "matches": 1, "error_code": None}
    return SimpleNamespace(**{**base, **kw})


def fake_discovery(
    monkeypatch: pytest.MonkeyPatch, c: Calls, outcomes: list[Any], reset: int = 1
) -> None:
    jobs = [uuid.uuid4() for _ in outcomes]

    def retry_failed(s: object, request_id: uuid.UUID, max_attempts: int | None = None) -> int:
        c.log.append(("retry_failed", max_attempts))
        return reset

    by_job = dict(zip(jobs, outcomes, strict=True))
    monkeypatch.setattr(
        tasks,
        "discovery",
        SimpleNamespace(
            start=lambda s, request_id, registry: c.log.append(("start", request_id)) or jobs,
            run_job=lambda engine, tenant_id, job_id, **kw: by_job[job_id],
            retry_failed=retry_failed,
            after_discovery=lambda s, request_id, registry: (
                c.log.append(("after", request_id)) or True
            ),
        ),
    )


# ---- run_discovery -------------------------------------------------------------------


def test_discovery_success_moves_the_case_on(calls: Calls, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_discovery(monkeypatch, calls, [outcome(), outcome()])
    tasks.run_discovery.run(TID, RID)
    assert calls.names() == ["session", "start", "session", "after"]
    assert calls.log[1][1] == uuid.UUID(RID)


def test_a_retryable_failure_resets_failed_jobs_and_asks_celery_to_retry(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_discovery(monkeypatch, calls, [outcome(), outcome(status="FAILED", retryable=True)])
    with pytest.raises(tasks.RetryableConnectorFailure):
        tasks.run_discovery.run(TID, RID)
    assert "retry_failed" in calls.names() and "after" not in calls.names()


def test_a_permanent_failure_is_not_retried(calls: Calls, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_discovery(monkeypatch, calls, [outcome(status="FAILED", retryable=False)])
    tasks.run_discovery.run(TID, RID)  # no exception: Celery must not retry
    assert "retry_failed" not in calls.names() and "after" in calls.names()


def test_automatic_retry_passes_the_attempt_cap(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_discovery(monkeypatch, calls, [outcome(status="FAILED", retryable=True)])
    with pytest.raises(tasks.RetryableConnectorFailure):
        tasks.run_discovery.run(TID, RID)
    assert ("retry_failed", 4) in calls.log


def test_when_attempts_are_used_up_celery_stops_and_the_case_is_left_for_staff(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_discovery(monkeypatch, calls, [outcome(status="FAILED", retryable=True)], reset=0)
    tasks.run_discovery.run(TID, RID)  # no exception: nothing left to retry automatically
    assert calls.names()[-1] == "after"  # same path as a permanent failure


def test_discovery_retries_are_bounded() -> None:
    t = tasks.run_discovery
    assert t.max_retries == 6 and t.retry_backoff and t.retry_backoff_max == 300
    assert t.autoretry_for == (tasks.RetryableConnectorFailure,)


# ---- run_fulfilment ------------------------------------------------------------------


def fake_fulfilment(monkeypatch: pytest.MonkeyPatch, c: Calls, results: list[Any]) -> None:
    ids = [uuid.uuid4() for _ in results]
    by_id = dict(zip(ids, results, strict=True))

    def dispatch(engine: object, tenant_id: uuid.UUID, task_id: uuid.UUID, **kw: Any) -> Any:
        c.log.append(("dispatch", kw["max_attempts"]))
        return by_id[task_id]

    monkeypatch.setattr(
        tasks,
        "fulfilment",
        SimpleNamespace(
            pending_tasks=lambda s, rid: ids,
            dispatch=dispatch,
            finish_if_complete=lambda s, request_id, registry: c.log.append(("finish", request_id)),
        ),
    )


@pytest.mark.parametrize(
    ("result", "retries"),
    [
        (outcome(status="SUCCEEDED"), False),
        (outcome(status="FAILED_FINAL", retryable=False), False),
        (outcome(status="FAILED_RETRYABLE", retryable=True), True),
        (outcome(status="BUSY"), True),  # another worker holds the task: try later
    ],
)
def test_fulfilment_retry_decision(
    calls: Calls, monkeypatch: pytest.MonkeyPatch, result: Any, retries: bool
) -> None:
    fake_fulfilment(monkeypatch, calls, [outcome(), result])
    if retries:
        with pytest.raises(tasks.RetryableConnectorFailure):
            tasks.run_fulfilment.run(TID, RID)
        assert "finish" not in calls.names()
    else:
        tasks.run_fulfilment.run(TID, RID)
        assert calls.names()[-1] == "finish"


def test_fulfilment_passes_the_configured_attempt_limit(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_fulfilment(monkeypatch, calls, [outcome()])
    tasks.run_fulfilment.run(TID, RID)
    assert ("dispatch", 3) in calls.log


def test_a_redelivered_fulfilment_message_with_nothing_pending_just_finishes(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_fulfilment(monkeypatch, calls, [])  # every task already terminal
    tasks.run_fulfilment.run(TID, RID)
    tasks.run_fulfilment.run(TID, RID)
    assert calls.names().count("dispatch") == 0 and calls.names().count("finish") == 2


# ---- disclosure export ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "retryable", "raises"),
    [("READY", False, False), ("FAILED", False, False), ("FAILED", True, True)],
)
def test_export_retries_only_retryable_failures(
    calls: Calls, monkeypatch: pytest.MonkeyPatch, status: str, retryable: bool, raises: bool
) -> None:
    result = outcome(status=status, retryable=retryable)
    monkeypatch.setattr(tasks, "disclosure", SimpleNamespace(run_export=lambda *a, **k: result))
    if raises:
        with pytest.raises(tasks.RetryableConnectorFailure):
            tasks.run_disclosure_export.run(TID, RID, str(uuid.uuid4()))
    else:
        tasks.run_disclosure_export.run(TID, RID, str(uuid.uuid4()))


# ---- single-call tasks: wiring and redelivery ----------------------------------------


def test_pipeline_task_converts_ids_and_tolerates_a_skip(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[uuid.UUID] = []

    def pipeline(session: object, request_id: uuid.UUID, **kw: Any) -> None:
        seen.append(request_id)
        return None  # already processed: a redelivered message

    monkeypatch.setattr(tasks, "run_pipeline", pipeline)
    tasks.process_verified_case.run(TID, RID)
    assert seen == [uuid.UUID(RID)] and calls.log == [("session", TID)]


def test_verification_and_evidence_tasks_pass_typed_ids(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    got: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    monkeypatch.setattr(
        tasks,
        "verification",
        SimpleNamespace(
            run=lambda engine, tenant_id, request_id, **kw: got.update(v=(tenant_id, request_id)),
            RetryLater=tasks.verification.RetryLater,
        ),
    )
    monkeypatch.setattr(
        tasks,
        "evidence",
        SimpleNamespace(
            generate=lambda engine, tenant_id, request_id, **kw: got.update(
                e=(tenant_id, request_id)
            ),
        ),
    )
    tasks.run_verification.run(TID, RID)
    tasks.generate_evidence.run(TID, RID)
    assert got["v"] == got["e"] == (uuid.UUID(TID), uuid.UUID(RID))


def test_access_report_builds_report_then_evidence(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []
    monkeypatch.setattr(
        tasks,
        "access_report",
        SimpleNamespace(
            build=lambda *a, **k: order.append("report"),
        ),
    )
    monkeypatch.setattr(
        tasks,
        "evidence",
        SimpleNamespace(
            generate=lambda *a, **k: order.append(f"evidence:{k['event']}"),
        ),
    )
    tasks.build_access_report.run(TID, RID, str(uuid.uuid4()))
    assert order == ["report", "evidence:REPORT_READY"]


def test_respond_and_close_builds_the_notifier_once(
    calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[object] = []
    monkeypatch.setattr(tasks, "_notifier", None)
    monkeypatch.setattr(
        tasks,
        "communications",
        SimpleNamespace(
            build_notifier=lambda settings: built.append(settings) or "notifier",
            respond_and_close=lambda s, **k: k["notifier"] == "notifier",
        ),
    )
    tasks.respond_and_close.run(TID, RID)
    tasks.respond_and_close.run(TID, RID)  # redelivery: no second notifier, no error
    assert len(built) == 1


def test_noop_task_runs() -> None:
    tasks.noop.run(TID, request_id=RID)


def test_the_attempt_cap_ends_discovery_retries_before_celery_does() -> None:
    from idprivacy.config import Settings

    default_cap = Settings.model_fields["discovery_max_attempts"].default
    assert default_cap <= tasks.run_discovery.max_retries
