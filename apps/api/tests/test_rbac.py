from fastapi.testclient import TestClient

from tests.conftest import bearer

VERIFY = "/v1/audit/verify"


def test_auditor_can_verify_chain(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    _, subject = provision_user(make_tenant(), ["AUDITOR"])
    r = client.post(VERIFY, headers=bearer(make_token(subject)))
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_other_roles_cannot_verify_chain(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    tenant = make_tenant()
    for role in ("PRIVACY_ANALYST", "APPROVER", "TENANT_ADMIN"):
        _, subject = provision_user(tenant, [role])
        assert client.post(VERIFY, headers=bearer(make_token(subject))).status_code == 403


def test_user_without_roles_is_forbidden_everywhere(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    _, subject = provision_user(make_tenant(), [])
    token = make_token(subject)
    assert client.get("/v1/me", headers=bearer(token)).status_code == 403
    assert client.post(VERIFY, headers=bearer(token)).status_code == 403


def test_verify_only_covers_callers_tenant(
    client: TestClient, make_tenant, provision_user, make_token, app_engine
) -> None:
    """Events in tenant B don't count toward tenant A's verification."""
    from idprivacy.domain.audit import service as audit
    from idprivacy.platform.db import TenantContext, tenant_session

    tenant_a, tenant_b = make_tenant(), make_tenant()
    with tenant_session(app_engine, TenantContext(tenant_b)) as s:
        for _ in range(3):
            audit.append(
                s,
                tenant_id=tenant_b,
                actor_type="SYSTEM",
                actor_ref="system:test",
                action="test.event",
                object_type="tenant",
                object_id=tenant_b,
            )
    _, subject = provision_user(tenant_a, ["AUDITOR"])
    r = client.post(VERIFY, headers=bearer(make_token(subject)))
    assert r.json()["events_checked"] == 0
