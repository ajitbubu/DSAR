from fastapi.testclient import TestClient

from idprivacy.main import create_app
from tests.conftest import make_settings


def _client(probes) -> TestClient:
    return TestClient(
        create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes=probes)
    )


def test_healthz() -> None:
    assert _client({}).get("/healthz").json() == {"status": "ok"}


def test_readyz_all_ok() -> None:
    r = _client({"database": lambda: None}).get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok"}


def test_readyz_failure_is_503_without_leaking_details() -> None:
    def boom() -> None:
        raise RuntimeError("password authentication failed for user idp_app at 10.0.0.5")

    r = _client({"database": boom, "redis": lambda: None}).get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "degraded", "checks": {"database": "fail", "redis": "ok"}}
    assert "password" not in r.text
