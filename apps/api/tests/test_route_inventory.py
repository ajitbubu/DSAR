"""Every route must declare Requires(<permission>) or Public() (ADR-0003)."""

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.routing import BaseRoute

from idprivacy.main import create_app
from idprivacy.platform.auth.deps import Public, Requires
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
    if isinstance(dep.call, Requires | Public):
        found.append(dep.call)
    for sub in dep.dependencies:
        found.extend(_markers(sub))
    return found


def test_every_route_declares_authorization() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    routes = _api_routes(app.routes)
    assert routes, "no routes discovered"
    undeclared = [f"{sorted(r.methods)} {r.path}" for r in routes if not _markers(r.dependant)]
    assert undeclared == [], f"routes without Requires()/Public(): {undeclared}"


def test_public_routes_are_an_explicit_allowlist() -> None:
    app = create_app(make_settings(), key_resolver=lambda _t: None, readiness_probes={})
    public = {
        r.path
        for r in _api_routes(app.routes)
        if any(isinstance(m, Public) for m in _markers(r.dependant))
    }
    assert public == {"/healthz", "/readyz"}
