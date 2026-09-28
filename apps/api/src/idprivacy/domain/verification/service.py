"""Verification and reconciliation (M7).

A connector's claim that it deleted something is never enough. Each task is checked
two ways: the connector's own ``verify_action``, and an independent rescan with the
requester's verified identifiers. Results are append-only, one round per run.
"""

import uuid
from dataclasses import dataclass
from uuid import UUID

from idprivacy_connector_sdk import (
    ConnectorError,
    DiscoveryRequest,
    VerifyRequest,
    idempotency_key,
)
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.discovery.service import ConnectorFactory, discovery_identifiers
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.platform import outbox
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    ConnectorConfig,
    DataMatch,
    FulfilmentTask,
    PrivacyRequest,
    VerificationResult,
)

ACTOR = SystemActor("system:verification")
EXPECTED = {
    "DELETE": "ABSENT",
    "ANONYMIZE": "ANONYMIZED",
    "RESTRICT": "RESTRICTED",
    "NOOP_RETAIN": "PRESENT",
}


class RetryLater(Exception):
    """A connector was temporarily unavailable; the whole run should be retried."""


def expected_state(task: FulfilmentTask) -> str:
    # A skipped task (RETAIN, or a legal hold arriving after approval) must leave the record.
    return "PRESENT" if task.status == "SKIPPED" else EXPECTED[task.action]


def latest_tasks(session: Session, request_id: UUID) -> list[FulfilmentTask]:
    """The most recent round's task for each match."""
    rows = session.execute(
        select(FulfilmentTask)
        .where(FulfilmentTask.request_id == request_id)
        .order_by(FulfilmentTask.data_match_id, FulfilmentTask.round.desc())
    ).scalars()
    latest: dict[UUID, FulfilmentTask] = {}
    for t in rows:
        latest.setdefault(t.data_match_id, t)
    return sorted(latest.values(), key=lambda t: str(t.data_match_id))


def judge(expected: str, observed: str | None, in_rescan: bool | None) -> bool:
    if observed is None or in_rescan is None:
        return False
    if expected in ("ABSENT", "ANONYMIZED"):
        return observed == expected and not in_rescan
    if expected == "RESTRICTED":
        return observed == "RESTRICTED"
    return observed in ("PRESENT", "RESTRICTED") and in_rescan


@dataclass(frozen=True)
class _Check:
    task_id: UUID
    match_id: UUID
    ref: str
    config_id: UUID
    expected: str


def run(
    engine: Engine,
    *,
    tenant_id: UUID,
    request_id: UUID,
    factory: ConnectorFactory,
    registry: PolicyRegistry,
    cipher: FieldCipher,
) -> str | None:
    """Returns "PASS" / "FAIL", or None if the case isn't awaiting verification."""
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        request = s.get(PrivacyRequest, request_id)
        if request is None or request.status != CaseStatus.VERIFICATION_IN_PROGRESS:
            return None
        checks = []
        for task in latest_tasks(s, request_id):
            match = s.get(DataMatch, task.data_match_id)
            assert match is not None
            checks.append(
                _Check(
                    task.id,
                    match.id,
                    match.source_record_ref,
                    task.connector_config_id,
                    expected_state(task),
                )
            )
        identifiers = discovery_identifiers(s, request=request, registry=registry, cipher=cipher)
        connectors = {
            c.id: factory(c)
            for c in s.execute(
                select(ConnectorConfig).where(ConnectorConfig.id.in_({c.config_id for c in checks}))
            ).scalars()
        }

    # Outside any transaction: rescan each source and ask each connector.
    rescanned: dict[UUID, set[str] | None] = {}
    for config_id, connector in connectors.items():
        try:
            refs: set[str] = set()
            token: str | None = None
            for _ in range(200):
                page = connector.discover(
                    DiscoveryRequest(identifiers=identifiers, page_size=100, page_token=token)
                )
                refs |= {m.source_record_ref for m in page.matches}
                token = page.next_page_token
                if token is None:
                    break
            rescanned[config_id] = refs
        except ConnectorError as exc:
            if exc.retryable:
                raise RetryLater(str(config_id)) from exc
            rescanned[config_id] = None
    observed: dict[UUID, str | None] = {}
    for c in checks:
        try:
            observed[c.task_id] = (
                connectors[c.config_id]
                .verify_action(VerifyRequest(source_record_ref=c.ref))
                .observed
            )
        except ConnectorError as exc:
            if exc.retryable:
                raise RetryLater(str(c.task_id)) from exc
            observed[c.task_id] = None

    with tenant_session(engine, ctx) as s:
        request = s.execute(
            select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
        ).scalar_one()
        if request.status != CaseStatus.VERIFICATION_IN_PROGRESS:
            return None
        round_no = 1 + (
            s.execute(
                select(func.coalesce(func.max(VerificationResult.round), 0)).where(
                    VerificationResult.request_id == request_id
                )
            ).scalar_one()
        )
        failures = 0
        for c in checks:
            found: set[str] | None = rescanned.get(c.config_id)
            in_rescan = None if found is None else c.ref in found
            ok = judge(c.expected, observed[c.task_id], in_rescan)
            failures += not ok
            s.add(
                VerificationResult(
                    tenant_id=tenant_id,
                    request_id=request_id,
                    fulfilment_task_id=c.task_id,
                    data_match_id=c.match_id,
                    round=round_no,
                    expected=c.expected,
                    observed_verify=observed[c.task_id],
                    observed_rescan=None
                    if in_rescan is None
                    else ("PRESENT" if in_rescan else "ABSENT"),
                    outcome="PASS" if ok else "FAIL",
                    note=None
                    if ok
                    else "connector claim and independent rescan disagree with the expected state",
                )
            )
        outcome = "PASS" if failures == 0 else "FAIL"
        fire(
            s,
            request,
            "VERIFICATION_PASSED" if outcome == "PASS" else "VERIFICATION_FAILED",
            actor=ACTOR,
            registry=registry,
        )
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="SYSTEM",
            actor_ref=ACTOR.ref,
            action="verification.completed",
            object_type="privacy_request",
            object_id=request_id,
            details={
                "round": round_no,
                "outcome": outcome,
                "checked": len(checks),
                "failed": failures,
            },
        )
        if outcome == "PASS":
            outbox.enqueue(
                s,
                tenant_id=tenant_id,
                topic="case.evidence_requested",
                payload={"request_id": request_id},
            )
    return outcome


class ReconcileRejected(ValueError):
    pass


def reconcile(
    session: Session, *, request: PrivacyRequest, principal_ref: str, registry: PolicyRegistry
) -> int:
    """Re-open fulfilment for failed records as a new round with new idempotency keys.

    A new key is essential: replaying the old key against a connector that claimed
    success would just return the old (false) result.
    """
    if request.status != CaseStatus.RECONCILIATION_REQUIRED:
        raise ReconcileRejected("case doesn't need reconciliation")
    last_round = session.execute(
        select(func.max(VerificationResult.round)).where(
            VerificationResult.request_id == request.id
        )
    ).scalar_one()
    failed = (
        session.execute(
            select(VerificationResult).where(
                VerificationResult.request_id == request.id,
                VerificationResult.round == last_round,
                VerificationResult.outcome == "FAIL",
            )
        )
        .scalars()
        .all()
    )
    tasks = {
        t.id: t
        for t in session.execute(
            select(FulfilmentTask).where(
                FulfilmentTask.id.in_([f.fulfilment_task_id for f in failed])
            )
        ).scalars()
    }
    if any(tasks[f.fulfilment_task_id].status == "SKIPPED" for f in failed):
        raise ReconcileRejected(
            "a record that should have been retained is missing; investigate manually"
        )
    created = 0
    for f in failed:
        old = tasks[f.fulfilment_task_id]
        new_id = uuid.uuid4()
        session.add(
            FulfilmentTask(
                id=new_id,
                tenant_id=old.tenant_id,
                request_id=old.request_id,
                data_match_id=old.data_match_id,
                retention_decision_id=old.retention_decision_id,
                approval_id=old.approval_id,
                connector_config_id=old.connector_config_id,
                round=old.round + 1,
                action=old.action,
                status="PENDING",
                attempt_count=0,
                idempotency_key=idempotency_key(
                    old.tenant_id, new_id, old.action, old.retention_decision_id, old.round + 1
                ),
            )
        )
        created += 1
    session.flush()
    fire(
        session,
        request,
        "START_FULFILMENT",
        actor=SystemActor("system:reconciliation"),
        registry=registry,
    )
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
        action="verification.reconciliation_started",
        object_type="privacy_request",
        object_id=request.id,
        details={"tasks": created, "verification_round": last_round},
    )
    return created
