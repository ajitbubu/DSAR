"""Pack-defined workflow execution (M2; ADR-0005)."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.domain.cases.lifecycle import InvalidTransition
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import GuardFailed, SystemActor, TransitionForbidden, fire
from idprivacy.platform.auth.rbac import RoleCode, StaffPrincipal
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from tests.test_jurisdiction_pipeline import run, verified_case

SYSTEM = SystemActor("system:test")


def staff(tenant: uuid.UUID, *roles: RoleCode) -> StaffPrincipal:
    return StaffPrincipal(uuid.uuid4(), tenant, "sub", frozenset(roles))


def _fire(
    client: TestClient,
    tenant: uuid.UUID,
    rid: uuid.UUID,
    event: str,
    actor: SystemActor | StaffPrincipal,
) -> str:
    with tenant_session(client.app.state.app_engine, TenantContext(tenant)) as s:  # type: ignore[attr-defined]
        req = s.get(PrivacyRequest, rid)
        assert req is not None
        return fire(s, req, event, actor=actor, registry=PolicyRegistry())


@pytest.fixture
def erasure_case(client: TestClient, make_tenant) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = make_tenant()
    rid = verified_case(client, tenant)
    run(client, tenant, rid)
    return tenant, rid


def test_system_events_follow_the_pack(
    client: TestClient, erasure_case, migrator_engine: Engine
) -> None:
    tenant, rid = erasure_case
    assert _fire(client, tenant, rid, "START_DISCOVERY", SYSTEM) == "DISCOVERY_IN_PROGRESS"
    with migrator_engine.connect() as conn:
        details = conn.execute(
            text(
                "SELECT details FROM audit_event WHERE object_id = :r AND action = "
                "'case.transitioned' ORDER BY seq DESC LIMIT 1"
            ),
            {"r": rid},
        ).scalar_one()
    assert details == {
        "event": "START_DISCOVERY",
        "from": "JURISDICTION_DETERMINED",
        "to": "DISCOVERY_IN_PROGRESS",
        "policy_pack": "DPDP@1.0.0",
        "workflow": "erasure",
    }


def test_events_not_defined_for_the_current_state_are_refused(
    client: TestClient, erasure_case
) -> None:
    tenant, rid = erasure_case
    for event in ("DISCOVERY_FINISHED", "APPROVE", "CLOSE", "MADE_UP_EVENT"):
        with pytest.raises(InvalidTransition):
            _fire(client, tenant, rid, event, SYSTEM)


def _to_retention_evaluated(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID) -> None:
    for event in ("START_DISCOVERY", "DISCOVERY_FINISHED", "RETENTION_EVALUATED"):
        _fire(client, tenant, rid, event, SYSTEM)


def test_user_transitions_enforce_permission_and_tenant(
    client: TestClient, erasure_case, make_tenant
) -> None:
    tenant, rid = erasure_case
    _to_retention_evaluated(client, tenant, rid)
    refused = [
        SYSTEM,  # user-only event
        staff(tenant, RoleCode.AUDITOR),  # lacks case:review
        staff(tenant, RoleCode.APPROVER),  # lacks case:review
        staff(make_tenant(), RoleCode.PRIVACY_ANALYST),  # other tenant
    ]
    for actor in refused:
        with pytest.raises(TransitionForbidden):
            _fire(client, tenant, rid, "BEGIN_REVIEW", actor)
    assert (
        _fire(client, tenant, rid, "BEGIN_REVIEW", staff(tenant, RoleCode.PRIVACY_ANALYST))
        == "UNDER_REVIEW"
    )


def test_system_cannot_be_impersonated_by_staff(client: TestClient, erasure_case) -> None:
    tenant, rid = erasure_case
    with pytest.raises(TransitionForbidden):
        _fire(client, tenant, rid, "START_DISCOVERY", staff(tenant, RoleCode.PRIVACY_ANALYST))


def test_unimplemented_guards_fail_closed(
    client: TestClient, erasure_case, connector_factory
) -> None:
    """APPROVE's guard lands in M5; until then approval is refused, never allowed."""
    from tests.test_discovery import discover_all
    from tests.test_retention import evaluate_case

    tenant, rid = erasure_case
    discover_all(client, tenant, rid, connector_factory)
    evaluate_case(client, tenant, rid)
    analyst = staff(tenant, RoleCode.PRIVACY_ANALYST)
    _fire(client, tenant, rid, "BEGIN_REVIEW", analyst)
    with tenant_session(client.app.state.app_engine, TenantContext(tenant)) as s:  # type: ignore[attr-defined]
        from idprivacy.domain.retention import service as retention

        for match_id, head in retention.current_decisions(s, rid).items():
            if head.decision == "MANUAL_REVIEW":
                retention.override(
                    s,
                    request=s.get(PrivacyRequest, rid),
                    match_id=match_id,
                    principal=analyst,
                    registry=PolicyRegistry(),
                    data=retention.OverrideInput(
                        "RETAIN",
                        "LEGAL_OBLIGATION",  # type: ignore[arg-type]
                        "Kept for statutory records.",
                        head.id,
                    ),
                )
    _fire(client, tenant, rid, "SUBMIT_FOR_APPROVAL", analyst)
    with pytest.raises(GuardFailed, match="approval_valid_for_version"):
        _fire(client, tenant, rid, "APPROVE", staff(tenant, RoleCode.APPROVER))


def test_manual_workflow_can_be_closed_by_an_analyst(client: TestClient, make_tenant) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant, rights=["GRIEVANCE"])
    run(client, tenant, rid)
    with pytest.raises(TransitionForbidden):
        _fire(client, tenant, rid, "CLOSE_MANUALLY", staff(tenant, RoleCode.AUDITOR))
    assert (
        _fire(client, tenant, rid, "CLOSE_MANUALLY", staff(tenant, RoleCode.PRIVACY_ANALYST))
        == "CLOSED"
    )


def test_case_without_a_pinned_pack_has_no_workflow(client: TestClient, make_tenant) -> None:
    tenant = make_tenant(packs=())
    rid = verified_case(client, tenant)
    run(client, tenant, rid)
    with pytest.raises(InvalidTransition, match="not bound"):
        _fire(client, tenant, rid, "CLOSE_MANUALLY", staff(tenant, RoleCode.PRIVACY_ANALYST))
