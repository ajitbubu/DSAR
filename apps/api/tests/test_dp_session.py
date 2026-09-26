"""Data Principal tracking sessions (M1; ADR-0003, threat model T-04, T-05)."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from tests.conftest import bff, tenant_slug
from tests.test_public_intake import SUBMIT, form

CASE = "/v1/public/case"


def _verified_session(client: TestClient, slug: str, email: str) -> tuple[str, str]:
    body = form(slug, contact={"channel": "EMAIL", "value": email})
    r = client.post(SUBMIT, json=body, headers=bff())
    cid = r.json()["challengeId"]
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    token = client.post(
        f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff()
    ).json()["sessionToken"]
    return r.json()["displayId"], token


@pytest.fixture
def slug(make_tenant) -> str:
    return tenant_slug(make_tenant())


def test_session_reads_only_its_own_case(client: TestClient, slug: str, make_tenant) -> None:
    display_a, token_a = _verified_session(client, slug, "a@example.in")
    display_b, token_b = _verified_session(client, tenant_slug(make_tenant()), "b@example.in")

    a = client.get(CASE, headers=bff(**{"X-DP-Session": token_a})).json()
    b = client.get(CASE, headers=bff(**{"X-DP-Session": token_b})).json()
    assert (a["displayId"], b["displayId"]) == (display_a, display_b)
    assert a["status"] == "In progress" and a["canCancel"] is True


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-DP-Session": "not-a-real-session"},
        {"X-DP-Session": "x" * 500},
    ],
)
def test_missing_or_bogus_session_is_401(client: TestClient, headers: dict[str, str]) -> None:
    assert client.get(CASE, headers=bff(**headers)).status_code == 401


def test_display_id_alone_grants_nothing(client: TestClient, slug: str) -> None:
    display, _ = _verified_session(client, slug, "c@example.in")
    assert client.get(CASE, params={"displayId": display}, headers=bff()).status_code == 401


def test_session_requires_bff_credential(client: TestClient, slug: str) -> None:
    _, token = _verified_session(client, slug, "d@example.in")
    assert client.get(CASE, headers={"X-DP-Session": token}).status_code == 401


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE dp_session SET idle_expires_at = now() - interval '1 s' WHERE request_id = :r",
        "UPDATE dp_session SET absolute_expires_at = now() - interval '1 s' WHERE request_id = :r",
        "UPDATE dp_session SET revoked_at = now() WHERE request_id = :r",
        "UPDATE tenant SET status = 'SUSPENDED' WHERE id = (SELECT tenant_id FROM privacy_request "
        "WHERE id = :r)",
    ],
)
def test_expired_revoked_or_suspended_session_is_401(
    client: TestClient, slug: str, migrator_engine: Engine, sql: str
) -> None:
    display, token = _verified_session(client, slug, "e@example.in")
    with migrator_engine.begin() as conn:
        rid = conn.execute(
            text("SELECT id FROM privacy_request WHERE display_id = :d"), {"d": display}
        ).scalar_one()
        conn.execute(text(sql), {"r": rid})
    assert client.get(CASE, headers=bff(**{"X-DP-Session": token})).status_code == 401


def test_touch_slides_idle_expiry_but_not_past_absolute(
    client: TestClient, slug: str, migrator_engine: Engine
) -> None:
    display, token = _verified_session(client, slug, "f@example.in")
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE dp_session SET idle_expires_at = now() + interval '5 s', "
                "absolute_expires_at = now() + interval '60 s' WHERE request_id = "
                "(SELECT id FROM privacy_request WHERE display_id = :d)"
            ),
            {"d": display},
        )
    assert client.get(CASE, headers=bff(**{"X-DP-Session": token})).status_code == 200
    with migrator_engine.connect() as conn:
        idle, absolute = conn.execute(
            text(
                "SELECT idle_expires_at, absolute_expires_at FROM dp_session WHERE request_id = "
                "(SELECT id FROM privacy_request WHERE display_id = :d)"
            ),
            {"d": display},
        ).one()
    assert idle == absolute


def test_cancel_then_cannot_cancel_again(
    client: TestClient, slug: str, migrator_engine: Engine
) -> None:
    display, token = _verified_session(client, slug, "g@example.in")
    headers = bff(**{"X-DP-Session": token})
    r = client.post(f"{CASE}/cancel", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "Cancelled" and r.json()["canCancel"] is False
    assert client.post(f"{CASE}/cancel", headers=headers).status_code == 409
    with migrator_engine.connect() as conn:
        status, closed = conn.execute(
            text("SELECT status, closed_at FROM privacy_request WHERE display_id = :d"),
            {"d": display},
        ).one()
    assert status == "CANCELLED" and closed is not None


def test_dp_session_is_not_a_staff_credential(client: TestClient, slug: str) -> None:
    _, token = _verified_session(client, slug, "h@example.in")
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
