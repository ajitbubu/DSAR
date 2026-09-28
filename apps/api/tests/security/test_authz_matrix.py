"""Generated authorisation matrix (M9; threat model T-08, T-09).

Every protected route is enumerated from the running app, so new routes are covered
automatically. For each: anonymous → 401; a provisioned user with no roles → 403;
for object routes, a user holding *every* role in another tenant → 404, never data.
"""

import re
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from idprivacy.platform.auth.deps import DataPrincipalSession, InternalBff, Public
from tests.conftest import bearer
from tests.test_route_inventory import _api_routes, _markers

ALL_ROLES = ["TENANT_ADMIN", "PRIVACY_ANALYST", "APPROVER", "AUDITOR"]
PARAM = re.compile(r"\{([a-z_]+)\}")
# A valid-looking body per mutating route, so cross-tenant checks reach the object lookup
# instead of stopping at request validation.
BODIES: dict[str, Any] = {
    "/v1/cases/{case_id}/transitions": {"event": "BEGIN_REVIEW", "expected_version": 1},
    "/v1/cases/{case_id}/matches/{match_id}/retention-decisions": {
        "decision": "RETAIN",
        "exception_code": "LEGAL_OBLIGATION",
        "exception_reason": "Cross-tenant probe reason.",
        "expected_current_id": str(uuid.uuid4()),
    },
    "/v1/cases/{case_id}/approvals": {
        "outcome": "APPROVED",
        "case_version": 1,
        "decision_set_sha256": "a" * 64,
    },
    "/v1/legal-holds": {
        "scope": "CASE",
        "case_id": None,
        "matter_ref": "PROBE-1",
        "reason": "Cross-tenant probe reason.",
    },
}


def staff_routes(client: TestClient) -> list[tuple[str, str]]:
    out = []
    for route in _api_routes(client.app.routes):  # type: ignore[attr-defined]
        markers = _markers(route.dependant)
        if any(isinstance(m, Public | InternalBff | DataPrincipalSession) for m in markers):
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            out.append((method, route.path))
    return out


def fill(path: str, ids: dict[str, str]) -> str:
    return PARAM.sub(lambda m: ids.get(m.group(1), str(uuid.uuid4())), path)


def call(client: TestClient, method: str, path: str, url: str, headers: dict[str, str]) -> Any:
    body = BODIES.get(path, {})
    headers = {**headers, "Idempotency-Key": uuid.uuid4().hex}
    if method == "GET":
        return client.get(url, headers=headers)
    if path == "/v1/cases/{case_id}/evidence":
        pdf = b"%PDF-1.7\n%%EOF\n"
        return client.post(url, headers=headers, files={"file": ("p.pdf", pdf, "application/pdf")})
    return client.request(method, url, json=body, headers=headers)


def test_matrix_covers_every_protected_route(client: TestClient) -> None:
    routes = staff_routes(client)
    assert len(routes) >= 25, routes  # guard against the enumeration silently breaking
    assert ("POST", "/v1/cases/{case_id}/approvals") in routes


def test_anonymous_requests_are_rejected_everywhere(client: TestClient) -> None:
    failures = []
    for method, path in staff_routes(client):
        r = call(client, method, path, fill(path, {}), {})
        if r.status_code != 401:
            failures.append((method, path, r.status_code))
    assert failures == []


def test_users_without_roles_are_forbidden_everywhere(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    _, sub = provision_user(make_tenant(), [])
    headers = bearer(make_token(sub))
    failures = []
    for method, path in staff_routes(client):
        r = call(client, method, path, fill(path, {}), headers)
        if r.status_code != 403:
            failures.append((method, path, r.status_code))
    assert failures == []


def test_other_tenants_never_reach_a_case(
    client: TestClient, packaged, make_tenant, provision_user, make_token, migrator_engine: Any
) -> None:
    """A user with every role, in another tenant, gets 404 on every object route."""
    from sqlalchemy import text

    rid = packaged["rid"]
    with migrator_engine.connect() as conn:
        ids = {
            "case_id": str(rid),
            "match_id": str(
                conn.execute(
                    text("SELECT id FROM data_match WHERE request_id = :r LIMIT 1"), {"r": rid}
                ).scalar_one()
            ),
            "task_id": str(
                conn.execute(
                    text("SELECT id FROM fulfilment_task WHERE request_id = :r LIMIT 1"), {"r": rid}
                ).scalar_one()
            ),
            "artifact_id": str(packaged["artifact"]),
            "hold_id": str(uuid.uuid4()),
        }
        display_id = conn.execute(
            text("SELECT display_id FROM privacy_request WHERE id = :r"), {"r": rid}
        ).scalar_one()
    BODIES["/v1/legal-holds"]["case_id"] = str(rid)
    _, sub = provision_user(make_tenant(), ALL_ROLES)
    headers = bearer(make_token(sub))
    failures = []
    for method, path in staff_routes(client):
        if "{" not in path and path != "/v1/legal-holds":
            continue
        if path == "/v1/legal-holds" and method == "GET":
            continue
        r = call(client, method, path, fill(path, ids), headers)
        if r.status_code != 404 or display_id in r.text:
            failures.append((method, path, r.status_code))
    assert failures == []


@pytest.mark.parametrize(
    "path", ["/v1/cases", "/v1/approvals/queue", "/v1/legal-holds", "/v1/dashboard/summary"]
)
def test_collections_never_list_other_tenants(
    client: TestClient, packaged, make_tenant, provision_user, make_token, path: str
) -> None:
    _, sub = provision_user(make_tenant(), ALL_ROLES)
    body = client.get(path, headers=bearer(make_token(sub))).text
    assert str(packaged["rid"]) not in body
