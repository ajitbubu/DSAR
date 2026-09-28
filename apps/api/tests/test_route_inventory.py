"""Every route must declare how it is authorised (ADR-0003).

Markers: Requires(<permission>) for staff, InternalBff()/DataPrincipalSession() for
public Data Principal routes (BFF-only), Public() for unauthenticated ops endpoints.
"""

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from idprivacy.main import create_app
from idprivacy.platform.auth.deps import DataPrincipalSession, InternalBff, Public, Requires
from tests.conftest import make_settings


def _api_routes(routes: list[BaseRoute]) -> list[APIRoute]:
    """Flatten routes. FastAPI >=0.14x wraps included routers; declarations must be route-level."""
    flat: list[APIRoute] = []
    for r in routes:
        if isinstance(r, APIRoute):
            flat.append(r)
        elif (inner := getattr(r, "original_router", None)) is not None:
            flat.extend(_api_routes(inner.routes))
    return flat


def _markers(dep: Dependant) -> list[object]:
    found: list[object] = []
    if isinstance(dep.call, Requires | Public | InternalBff | DataPrincipalSession):
        found.append(dep.call)
    for sub in dep.dependencies:
        found.extend(_markers(sub))
    return found


def test_every_route_declares_authorization() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    routes = _api_routes(app.routes)
    assert routes, "no routes discovered"
    undeclared = [f"{sorted(r.methods)} {r.path}" for r in routes if not _markers(r.dependant)]
    assert undeclared == [], f"routes without an authorisation marker: {undeclared}"


def test_public_routes_are_an_explicit_allowlist() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    public = {
        r.path
        for r in _api_routes(app.routes)
        if any(isinstance(m, Public) for m in _markers(r.dependant))
    }
    assert public == {"/healthz", "/readyz"}


def test_every_public_dp_route_requires_the_bff_credential() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    public_dp = [r for r in _api_routes(app.routes) if r.path.startswith("/v1/public")]
    assert public_dp
    missing = [
        r.path
        for r in public_dp
        if not any(isinstance(m, InternalBff) for m in _markers(r.dependant))
    ]
    assert missing == []


def test_test_support_routes_only_exist_in_test_env() -> None:
    def paths(env: str) -> set[str]:
        app = create_app(make_settings(env=env), key_resolver=lambda _t: None, readiness_probes={})
        return {r.path for r in _api_routes(app.routes)}

    assert any(p.startswith("/v1/test-support") for p in paths("test"))
    assert not any(p.startswith("/v1/test-support") for p in paths("local"))


def test_rate_limit_reset_is_test_only_and_bff_only() -> None:
    from fastapi.testclient import TestClient

    from tests.conftest import bff

    test_app = TestClient(
        create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    )
    assert test_app.post("/v1/test-support/rate-limits/reset").status_code == 401
    assert test_app.post("/v1/test-support/rate-limits/reset", headers=bff()).status_code == 204
    local_app = TestClient(
        create_app(make_settings(env="local"), key_resolver=lambda _t: None, readiness_probes={})
    )
    assert local_app.post("/v1/test-support/rate-limits/reset", headers=bff()).status_code == 404
