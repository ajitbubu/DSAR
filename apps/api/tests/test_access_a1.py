"""Right to Access, milestone A1: export plumbing and DPDP 1.1.0 (docs/milestones-access.md)."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.domain.discovery import service as discovery
from idprivacy.domain.policy.loader import load_all, read_yaml
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import GuardFailed, fire
from idprivacy.platform.auth.rbac import RoleCode, StaffPrincipal
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from tests.conftest import POLICY_PACKS
from tests.test_discovery import _verified_with, discover_all
from tests.test_jurisdiction_pipeline import run
from tests.test_public_intake import form
from tests.test_retention import status_of

V11 = (("DPDP", "1.1.0"),)


def _pack(version: str) -> dict[str, Any]:
    return read_yaml(POLICY_PACKS / "dpdp" / version / "pack.yaml")


def test_both_versions_are_pinned_and_load() -> None:
    refs = {p.pack.ref for p in load_all(POLICY_PACKS)}
    assert {"DPDP@1.0.0", "DPDP@1.1.0"} <= refs


def test_1_1_0_changes_only_what_it_says() -> None:
    old, new = _pack("1.0.0"), _pack("1.1.0")
    assert new["rights"]["ACCESS"]["executable"] is True
    assert new["rights"]["ACCESS"]["workflow"] == "access"
    assert old["rights"]["ACCESS"]["executable"] is False
    assert new["workflows"]["erasure"] == old["workflows"]["erasure"]
    assert new["retention_rules"] == old["retention_rules"]
    for right in ("ERASURE", "CORRECTION", "CONSENT_WITHDRAWAL", "GRIEVANCE", "NOMINATION"):
        assert new["rights"][right] == old["rights"][right]
    assert "THIRD_PARTY_DATA" in {c["code"] for c in new["exception_codes"]}


def access_case(client: TestClient, tenant: uuid.UUID) -> uuid.UUID:
    rid = _verified_with(
        client,
        tenant,
        form(
            "", rights=["ACCESS"], contact={"channel": "EMAIL", "value": "priya.sharma@example.in"}
        ),
    )
    assert run(client, tenant, rid) == "JURISDICTION_DETERMINED"
    return rid


def after(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID) -> str | None:
    with tenant_session(client.app.state.app_engine, TenantContext(tenant)) as s:  # type: ignore[attr-defined]
        return discovery.after_discovery(s, request_id=rid, registry=PolicyRegistry())


def test_access_case_is_pinned_to_the_access_workflow(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant(packs=V11)
    rid = access_case(client, tenant)
    with migrator_engine.connect() as conn:
        workflow, pack = conn.execute(
            text(
                "SELECT r.workflow_code, p.version FROM privacy_request r JOIN policy_pack p "
                "ON p.id = r.policy_pack_id WHERE r.id = :r"
            ),
            {"r": rid},
        ).one()
    assert (workflow, pack) == ("access", "1.1.0")


def test_access_discovery_skips_retention(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant(packs=V11)
    rid = access_case(client, tenant)
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        jobs = discovery.start(s, request_id=rid, registry=PolicyRegistry())
    for job in jobs:
        discovery.run_job(
            state.app_engine,
            tenant_id=tenant,
            job_id=job,
            factory=connector_factory,
            registry=PolicyRegistry(),
            cipher=state.cipher,
        )
    assert after(client, tenant, rid) == "DISCOVERY_COMPLETE"
    assert status_of(migrator_engine, rid)[0] == "DISCOVERY_COMPLETE"
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM retention_decision WHERE request_id = :r"), {"r": rid}
        ).scalar_one()
    assert n == 0  # access changes nothing, so nothing gets a retention decision


def test_erasure_under_1_1_0_still_evaluates_retention(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant(packs=V11)
    rid = _verified_with(
        client, tenant, form("", contact={"channel": "EMAIL", "value": "priya.sharma@example.in"})
    )
    run(client, tenant, rid)
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        jobs = discovery.start(s, request_id=rid, registry=PolicyRegistry())
    for job in jobs:
        discovery.run_job(
            state.app_engine,
            tenant_id=tenant,
            job_id=job,
            factory=connector_factory,
            registry=PolicyRegistry(),
            cipher=state.cipher,
        )
    assert after(client, tenant, rid) == "RETENTION_EVALUATED"
    assert status_of(migrator_engine, rid)[0] == "RETENTION_EVALUATED"


def test_access_review_starts_but_submission_fails_closed_until_a2(
    client: TestClient, make_tenant, connector_factory
) -> None:
    tenant = make_tenant(packs=V11)
    rid = access_case(client, tenant)
    discover_all(client, tenant, rid, connector_factory)  # finish_if_complete only
    analyst = StaffPrincipal(uuid.uuid4(), tenant, "sub", frozenset({RoleCode.PRIVACY_ANALYST}))
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        case = s.get(PrivacyRequest, rid)
        assert case is not None
        assert (
            fire(s, case, "BEGIN_REVIEW", actor=analyst, registry=PolicyRegistry())
            == "UNDER_REVIEW"
        )
    with pytest.raises(GuardFailed, match="disclosure_reviewed"):
        with tenant_session(state.app_engine, TenantContext(tenant)) as s:
            case = s.get(PrivacyRequest, rid)
            assert case is not None
            fire(s, case, "SUBMIT_FOR_APPROVAL", actor=analyst, registry=PolicyRegistry())


def test_access_stays_manual_under_1_0_0(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant()  # DPDP@1.0.0
    rid = _verified_with(
        client,
        tenant,
        form(
            "", rights=["ACCESS"], contact={"channel": "EMAIL", "value": "priya.sharma@example.in"}
        ),
    )
    assert run(client, tenant, rid) == "PENDING_MANUAL_HANDLING"  # not executable in 1.0.0
