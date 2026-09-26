"""Negative JWT tests through the real HTTP stack (threat T-10)."""

import base64
import hashlib
import hmac
import json
import time
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import bearer

ME = "/v1/me"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64json(obj: object) -> str:
    return _b64(json.dumps(obj).encode())


@pytest.fixture
def analyst(make_tenant, provision_user) -> tuple[UUID, str]:
    tenant = make_tenant()
    _, subject = provision_user(tenant, ["PRIVACY_ANALYST"])
    return tenant, subject


def test_valid_token_for_provisioned_user(client: TestClient, make_token, analyst) -> None:
    tenant, subject = analyst
    r = client.get(ME, headers=bearer(make_token(subject)))
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == str(tenant)
    assert body["roles"] == ["PRIVACY_ANALYST"]


def test_missing_authorization_header(client: TestClient) -> None:
    r = client.get(ME)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("header", ["Basic abc", "Bearer", "Bearer ", "token-only", "Bearer x.y.z"])
def test_malformed_authorization_header(client: TestClient, header: str) -> None:
    assert client.get(ME, headers={"Authorization": header}).status_code == 401


def test_oversized_token(client: TestClient) -> None:
    assert client.get(ME, headers=bearer("a" * 9000)).status_code == 401


def test_alg_none_rejected(client: TestClient, analyst) -> None:
    _, subject = analyst
    now = int(time.time())
    token = jwt.encode(
        {"iss": "x", "aud": "idprivacy-api", "sub": subject, "iat": now, "exp": now + 60},
        key=None,
        algorithm="none",
    )
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_hs256_key_confusion_rejected(
    client: TestClient, make_token, analyst, public_pem: bytes
) -> None:
    """Classic attack: sign HS256 using the RSA public key as the HMAC secret."""
    _, subject = analyst
    now = int(time.time())
    signing_input = (
        _b64json({"alg": "HS256", "typ": "JWT"})
        + "."
        + _b64json(
            {
                "iss": "https://idp.test.invalid/realms/idprivacy",
                "aud": "idprivacy-api",
                "sub": subject,
                "iat": now,
                "exp": now + 60,
            }
        )
    )
    sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    forged = f"{signing_input}.{_b64(sig)}"
    assert client.get(ME, headers=bearer(forged)).status_code == 401


def test_signature_from_untrusted_key_rejected(
    client: TestClient, make_token, analyst, other_rsa_key: rsa.RSAPrivateKey
) -> None:
    _, subject = analyst
    assert client.get(ME, headers=bearer(make_token(subject, key=other_rsa_key))).status_code == 401


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "some-other-api"},
        {"iss": "https://evil.example/realms/idprivacy"},
        {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200},
        {"nbf": int(time.time()) + 3600},
    ],
)
def test_bad_claims_rejected(client: TestClient, make_token, analyst, claims) -> None:
    _, subject = analyst
    assert client.get(ME, headers=bearer(make_token(subject, **claims))).status_code == 401


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "aud", "iss"])
def test_required_claims_enforced(client: TestClient, make_token, analyst, missing: str) -> None:
    _, subject = analyst
    assert client.get(ME, headers=bearer(make_token(subject, drop=(missing,)))).status_code == 401


def test_tampered_payload_rejected(client: TestClient, make_token, analyst) -> None:
    _, subject = analyst
    head, body, sig = make_token(subject).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["sub"] = "someone-else"
    body2 = _b64json(claims)
    assert client.get(ME, headers=bearer(f"{head}.{body2}.{sig}")).status_code == 401


def test_valid_token_but_unprovisioned_user_forbidden(client: TestClient, make_token) -> None:
    assert client.get(ME, headers=bearer(make_token("never-provisioned"))).status_code == 403


def test_disabled_tenant_forbidden(
    client: TestClient, make_token, analyst, migrator_engine
) -> None:
    tenant, subject = analyst
    with migrator_engine.begin() as conn:
        conn.execute(text("UPDATE tenant SET status='SUSPENDED' WHERE id=:t"), {"t": tenant})
    assert client.get(ME, headers=bearer(make_token(subject))).status_code == 403
