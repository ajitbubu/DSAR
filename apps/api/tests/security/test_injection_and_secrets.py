"""SQL injection (T-25) and connector credential handling (T-14)."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from idprivacy.platform import secrets
from tests.conftest import bff, make_settings, tenant_slug
from tests.test_public_intake import SUBMIT, form

SRC = Path(__file__).resolve().parents[2] / "src" / "idprivacy"
# text() built from an f-string or string concatenation is the classic injection shape.
UNSAFE_SQL = re.compile(r"text\(\s*f[\"']|text\([^)]*\+\s*\w")


def test_no_sql_is_built_from_interpolated_strings() -> None:
    offenders = [
        f"{p.relative_to(SRC)}:{n}"
        for p in SRC.rglob("*.py")
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if UNSAFE_SQL.search(line)
    ]
    assert offenders == []


def test_rule_detects_the_unsafe_shape() -> None:
    assert UNSAFE_SQL.search('conn.execute(text(f"SELECT * FROM t WHERE id = {x}"))')
    assert not UNSAFE_SQL.search('conn.execute(text("SELECT * FROM t WHERE id = :x"), {"x": 1})')


@pytest.mark.parametrize(
    "payload",
    [
        "Robert'); DROP TABLE tenant;--",
        "' OR '1'='1",
        'x"; SELECT pg_sleep(5); --',
    ],
)
def test_injection_payloads_are_just_data(
    client: TestClient, make_tenant, payload: str, migrator_engine
) -> None:  # type: ignore[no-untyped-def]
    from sqlalchemy import text

    tenant = make_tenant()
    r = client.post(
        SUBMIT, json=form(tenant_slug(tenant), fullName=payload, details=payload), headers=bff()
    )
    assert r.status_code == 202
    with migrator_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM tenant WHERE id = :t"), {"t": tenant}
            ).scalar_one()
            == 1
        )


def test_connector_credentials_resolve_by_reference_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOME_CONNECTOR_TOKEN", "s3cret-value")
    assert secrets.resolve("env:SOME_CONNECTOR_TOKEN") == "s3cret-value"
    for ref in ("vault:x", "SOME_CONNECTOR_TOKEN", "env:", "env:MISSING_TOKEN_XYZ"):
        with pytest.raises(secrets.SecretNotFound):
            secrets.resolve(ref)


def test_env_connector_secrets_refused_outside_dev() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="env connector secrets"):
        make_settings(env="staging")


def test_api_responses_carry_security_headers(client: TestClient) -> None:
    for path in ("/healthz", "/v1/me"):
        r = client.get(path)
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in r.headers["content-security-policy"]
    assert client.get("/v1/me").headers["cache-control"] == "no-store"


@pytest.mark.parametrize("value", ["10", "0/600", "10/0", "a/b", "10/999999", "-1/60"])
def test_rate_limit_settings_are_validated(value: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="hits/seconds"):
        make_settings(rate_limit_submit_per_ip=value)


def test_rate_limits_come_from_settings(make_tenant, rsa_key) -> None:  # type: ignore[no-untyped-def]
    from idprivacy.main import create_app

    app = create_app(
        make_settings(rate_limit_submit_per_ip="2/60"),
        key_resolver=lambda _t: rsa_key.public_key(),
        readiness_probes={},
    )
    c = TestClient(app)
    codes = [
        c.post(
            SUBMIT,
            json=form(
                tenant_slug(make_tenant()),
                contact={"channel": "EMAIL", "value": f"u{i}@example.in"},
            ),
            headers=bff(ip="198.51.100.200"),
        ).status_code
        for i in range(3)
    ]
    assert codes == [202, 202, 429]
