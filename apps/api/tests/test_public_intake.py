"""Public erasure intake (M1; threat model T-01, T-04, T-17, T-24)."""

import re
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from tests.conftest import bff, tenant_slug

SUBMIT = "/v1/public/requests"
EMAIL = "Priya.Sharma@Example.co.in"
NAME = "Priya Sharma"


def form(slug: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "intakeSlug": slug,
        "rights": ["ERASURE"],
        "fullName": NAME,
        "contact": {"channel": "EMAIL", "value": EMAIL},
        "additionalIdentifiers": [{"type": "CUSTOMER_ID", "value": "CUST-1001"}],
        "details": "Please delete my account and marketing data.",
        "residencyClaim": "IN",
        "consentToProcess": True,
    }
    body.update(overrides)
    return body


@pytest.fixture
def slug(make_tenant) -> str:
    return tenant_slug(make_tenant())


def test_valid_submission_creates_pending_case(
    client: TestClient, slug: str, migrator_engine: Engine
) -> None:
    r = client.post(SUBMIT, json=form(slug), headers=bff())
    assert r.status_code == 202
    body = r.json()
    assert re.fullmatch(r"DPR-\d{4}-[0-9A-HJKMNP-TV-Z]{6}", body["displayId"])
    assert body["destinationHint"] == "p•••@e•••.in"
    uuid.UUID(body["challengeId"])

    with migrator_engine.connect() as conn:
        req = conn.execute(
            text(
                "SELECT id, tenant_id, status, version FROM privacy_request WHERE display_id = :d"
            ),
            {"d": body["displayId"]},
        ).one()
        assert req.status == "PENDING_VERIFICATION"
        actions = (
            conn.execute(
                text("SELECT action FROM audit_event WHERE tenant_id = :t ORDER BY seq"),
                {"t": req.tenant_id},
            )
            .scalars()
            .all()
        )
    assert actions == ["request.submitted", "identity.challenge_issued", "case.transitioned"]


def test_personal_data_and_otp_are_not_stored_in_plaintext(
    client: TestClient, slug: str, migrator_engine: Engine
) -> None:
    r = client.post(SUBMIT, json=form(slug), headers=bff())
    challenge_id = uuid.UUID(r.json()["challengeId"])
    code = client.app.state.otp_provider.peek(challenge_id)  # type: ignore[attr-defined]
    assert code and re.fullmatch(r"\d{6}", code)

    needles = [EMAIL.lower(), "priya", "sharma", "cust-1001", "marketing"]
    with migrator_engine.connect() as conn:
        tenant = conn.execute(
            text("SELECT tenant_id FROM identity_verification WHERE id = :c"), {"c": challenge_id}
        ).scalar_one()
        # A 6-digit code can occur by chance inside hex; check no field *is* the code.
        row = conn.execute(
            text("SELECT * FROM identity_verification WHERE id = :c"), {"c": challenge_id}
        ).one()
        assert code not in {str(v) for v in row}
        for table in (
            "data_principal",
            "privacy_request",
            "request_right",
            "identity_verification",
            "audit_event",
        ):
            rows = (
                conn.execute(
                    text(f"SELECT row_to_json(t)::text FROM {table} t WHERE tenant_id = :t"),
                    {"t": tenant},
                )
                .scalars()
                .all()
            )
            dump = " ".join(rows).lower()
            for needle in needles:
                assert needle.lower() not in dump, f"{needle!r} found in {table}"


def test_same_contact_reuses_data_principal(
    client: TestClient, slug: str, migrator_engine: Engine
) -> None:
    client.post(SUBMIT, json=form(slug), headers=bff())
    upper = form(slug, contact={"channel": "EMAIL", "value": EMAIL.upper()})
    client.post(SUBMIT, json=upper, headers=bff())
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text(
                "SELECT count(DISTINCT data_principal_id) FROM privacy_request pr "
                "JOIN tenant t ON t.id = pr.tenant_id WHERE t.slug = :s"
            ),
            {"s": slug},
        ).scalar_one()
    assert n == 1


@pytest.mark.parametrize(
    "headers", [{}, {"X-Internal-Auth": "wrong-secret"}, {"X-Internal-Auth": ""}]
)
def test_requires_bff_credential(client: TestClient, slug: str, headers: dict[str, str]) -> None:
    assert client.post(SUBMIT, json=form(slug), headers=headers).status_code == 401


def test_unknown_or_suspended_tenant_is_404(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    assert client.post(SUBMIT, json=form("no-such-tenant"), headers=bff()).status_code == 404
    tenant = make_tenant()
    with migrator_engine.begin() as conn:
        conn.execute(text("UPDATE tenant SET status = 'SUSPENDED' WHERE id = :t"), {"t": tenant})
    assert client.post(SUBMIT, json=form(tenant_slug(tenant)), headers=bff()).status_code == 404


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "CLOSED"},  # mass assignment
        {"tenantId": str(uuid.uuid4())},  # tenant injection
        {"fullName": "x" * 201},
        {"fullName": ""},
        {"fullName": "Priya\x00Sharma"},
        {"details": "d" * 2001},
        {"contact": {"channel": "EMAIL", "value": "not-an-email"}},
        {"contact": {"channel": "SMS", "value": "98765 43210"}},
        {"contact": {"channel": "FAX", "value": "+919876543210"}},
        {"contact": {"channel": "EMAIL", "value": EMAIL, "extra": "x"}},
        {"rights": []},
        {"rights": ["ERASURE", "ACCESS"]},
        {"rights": ["DELETE_EVERYTHING"]},
        {"consentToProcess": False},
        {"intakeSlug": "../../etc"},
        {"additionalIdentifiers": [{"type": "CUSTOMER_ID", "value": "a b"}]},
        {"additionalIdentifiers": [{"type": "CUSTOMER_ID", "value": "x"}] * 6},
        {"residencyClaim": "MARS"},
    ],
)
def test_malformed_input_rejected(client: TestClient, slug: str, overrides: dict[str, Any]) -> None:
    r = client.post(SUBMIT, json=form(slug, **overrides), headers=bff())
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/problem+json")


def test_validation_errors_do_not_echo_input(client: TestClient, slug: str) -> None:
    secret_ish = "leaky-value-" + "z" * 250
    r = client.post(SUBMIT, json=form(slug, fullName=secret_ish), headers=bff())
    assert r.status_code == 422
    assert "leaky-value" not in r.text


def test_missing_required_fields(client: TestClient, slug: str) -> None:
    body = form(slug)
    del body["fullName"], body["consentToProcess"]
    assert client.post(SUBMIT, json=body, headers=bff()).status_code == 422


def test_sms_contact_accepted(client: TestClient, slug: str) -> None:
    r = client.post(
        SUBMIT, json=form(slug, contact={"channel": "SMS", "value": "+919876543210"}), headers=bff()
    )
    assert r.status_code == 202
    assert r.json()["destinationHint"] == "+91•••••210"


def test_oversized_declared_body_is_413(client: TestClient, slug: str) -> None:
    padding = "x" * (65 * 1024)
    r = client.post(
        SUBMIT,
        content='{"pad":"' + padding + '"}',
        headers={**bff(), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_oversized_streamed_body_is_413(client: TestClient, slug: str) -> None:
    def chunks():  # type: ignore[no-untyped-def]
        yield b'{"pad":"'
        for _ in range(70):
            yield b"x" * 1024
        yield b'"}'

    r = client.post(SUBMIT, content=chunks(), headers={**bff(), "Content-Type": "application/json"})
    assert r.status_code == 413


def test_non_json_body_rejected(client: TestClient, slug: str) -> None:
    r = client.post(
        SUBMIT,
        content="fullName=x",
        headers={**bff(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 422


def test_rate_limit_per_ip(client: TestClient, make_tenant) -> None:
    statuses = []
    for i in range(11):
        slug = tenant_slug(make_tenant())  # distinct tenants: isolate the per-IP limit
        body = form(slug, contact={"channel": "EMAIL", "value": f"user{i}@example.in"})
        statuses.append(client.post(SUBMIT, json=body, headers=bff(ip="198.51.100.1")))
    assert [r.status_code for r in statuses[:10]] == [202] * 10
    assert statuses[10].status_code == 429
    assert int(statuses[10].headers["retry-after"]) > 0


def test_rate_limit_per_contact_stops_otp_bombing(client: TestClient, slug: str) -> None:
    codes = [
        client.post(SUBMIT, json=form(slug), headers=bff(ip=f"198.51.100.{i}")).status_code
        for i in range(10, 14)
    ]
    assert codes == [202, 202, 202, 429]
