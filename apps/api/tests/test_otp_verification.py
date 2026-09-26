"""OTP verification (M1; threat model T-02, T-03, T-20)."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.main import create_app
from tests.conftest import bff, make_settings, tenant_slug
from tests.test_public_intake import SUBMIT, form


def _confirm(client: TestClient, challenge: str, code: str, ip: str = "203.0.113.7") -> Any:
    return client.post(
        f"/v1/public/verifications/{challenge}/confirm", json={"code": code}, headers=bff(ip=ip)
    )


def _wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


@pytest.fixture
def challenge(client: TestClient, make_tenant) -> tuple[str, str]:
    r = client.post(SUBMIT, json=form(tenant_slug(make_tenant())), headers=bff())
    cid = r.json()["challengeId"]
    return cid, client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]


def _state(engine: Engine, cid: str) -> tuple[str, int, str]:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT v.status, v.attempts, r.status AS case_status FROM identity_verification v "
                "JOIN privacy_request r ON r.id = v.request_id WHERE v.id = :c"
            ),
            {"c": cid},
        ).one()
    return row.status, row.attempts, row.case_status


def test_correct_code_verifies_and_issues_session(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, code = challenge
    r = _confirm(client, cid, code)
    assert r.status_code == 200
    token = r.json()["sessionToken"]
    assert len(token) >= 40
    assert _state(migrator_engine, cid) == ("VERIFIED", 0, "VERIFIED")
    with migrator_engine.connect() as conn:
        stored = conn.execute(
            text(
                "SELECT token_hash FROM dp_session s JOIN identity_verification"
                " v ON v.request_id = s.request_id WHERE v.id = :c"
            ),
            {"c": cid},
        ).scalar_one()
    assert stored != token and token not in stored


def test_five_wrong_attempts_lock_the_challenge(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, code = challenge
    for _ in range(5):
        r = _confirm(client, cid, _wrong(code))
        assert r.status_code == 422
    assert _state(migrator_engine, cid) == ("FAILED", 5, "VERIFICATION_FAILED")
    sixth = _confirm(client, cid, code)  # even the right code is refused now
    assert sixth.status_code == 429


def test_replayed_challenge_is_409(client: TestClient, challenge, migrator_engine: Engine) -> None:
    cid, code = challenge
    assert _confirm(client, cid, code).status_code == 200
    assert _confirm(client, cid, code).status_code == 409
    with migrator_engine.connect() as conn:
        actions = (
            conn.execute(text("SELECT action FROM audit_event WHERE object_id = :c"), {"c": cid})
            .scalars()
            .all()
        )
    assert "identity.challenge_replayed" in actions


def test_expired_code_is_410(client: TestClient, challenge, migrator_engine: Engine) -> None:
    cid, code = challenge
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE identity_verification SET expires_at = now() - interval '1 s' WHERE id = :c"
            ),
            {"c": cid},
        )
    assert _confirm(client, cid, code).status_code == 410
    assert _state(migrator_engine, cid)[0] == "EXPIRED"


def test_unknown_challenge_is_404(client: TestClient) -> None:
    assert _confirm(client, str(uuid.uuid4()), "123456").status_code == 404


@pytest.mark.parametrize("code", ["12345", "1234567", "abcdef", "12 456", ""])
def test_malformed_code_is_422_and_not_counted(
    client: TestClient, challenge, code: str, migrator_engine: Engine
) -> None:
    cid, _ = challenge
    assert _confirm(client, cid, code).status_code == 422
    assert _state(migrator_engine, cid)[1] == 0


def test_confirm_requires_bff_credential(client: TestClient, challenge) -> None:
    cid, code = challenge
    r = client.post(f"/v1/public/verifications/{cid}/confirm", json={"code": code})
    assert r.status_code == 401


def test_concurrent_guesses_are_counted_exactly(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, code = challenge
    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(
            pool.map(
                lambda i: _confirm(client, cid, _wrong(code), ip=f"192.0.2.{i}").status_code,
                range(10),
            )
        )
    assert sorted(statuses) == [422] * 5 + [429] * 5
    assert _state(migrator_engine, cid) == ("FAILED", 5, "VERIFICATION_FAILED")


def _resend(client: TestClient, cid: str) -> Any:
    return client.post(f"/v1/public/verifications/{cid}/resend", headers=bff())


def _age_last_send(engine: Engine, cid: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE identity_verification SET last_sent_at = now() - "
                "interval '1 hour' WHERE id = :c"
            ),
            {"c": cid},
        )


def test_resend_replaces_code_without_resetting_attempts(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, old_code = challenge
    assert _confirm(client, cid, _wrong(old_code)).status_code == 422
    assert _resend(client, cid).status_code == 429  # too soon
    _age_last_send(migrator_engine, cid)
    assert _resend(client, cid).status_code == 202
    new_code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    assert _state(migrator_engine, cid)[1] == 1
    if new_code != old_code:
        assert _confirm(client, cid, old_code).status_code == 422
    assert _confirm(client, cid, new_code).status_code == 200


def test_resend_revives_expired_challenge(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, code = challenge
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE identity_verification SET expires_at = now() - interval '1 s',"
                " last_sent_at = now() - interval '1 hour' WHERE id = :c"
            ),
            {"c": cid},
        )
    assert _confirm(client, cid, code).status_code == 410
    assert _resend(client, cid).status_code == 202
    new_code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    assert _confirm(client, cid, new_code).status_code == 200


def test_resend_limit(client: TestClient, challenge, migrator_engine: Engine) -> None:
    cid, _ = challenge
    for _ in range(3):
        _age_last_send(migrator_engine, cid)
        assert _resend(client, cid).status_code == 202
    _age_last_send(migrator_engine, cid)
    assert _resend(client, cid).status_code == 429


def test_resend_after_verification_is_409(
    client: TestClient, challenge, migrator_engine: Engine
) -> None:
    cid, code = challenge
    _confirm(client, cid, code)
    _age_last_send(migrator_engine, cid)
    assert _resend(client, cid).status_code == 409


def test_mock_otp_endpoint_only_in_test_env(client: TestClient, challenge) -> None:
    cid, code = challenge
    url = f"/v1/test-support/otp/{cid}"
    assert client.get(url, headers=bff()).json() == {"code": code}
    assert client.get(url).status_code == 401
    local = TestClient(
        create_app(make_settings(env="local"), key_resolver=lambda _t: None, readiness_probes={})
    )
    assert local.get(url, headers=bff()).status_code == 404
