"""FastAPI dependencies for authentication, authorization and tenant-scoped DB access.

The tenant comes only from the authenticated principal, resolved through the
``resolve_staff_principal`` SECURITY DEFINER function. It is never read from
client-supplied headers, paths or bodies. Public Data Principal routes resolve the tenant
from an opaque server-side handle (intake slug, challenge id, session token) instead.
"""

import hmac
import ipaddress
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from idprivacy.platform.auth import dp_session
from idprivacy.platform.auth.dp_session import DataPrincipalPrincipal
from idprivacy.platform.auth.oidc import InvalidTokenError, OidcVerifier
from idprivacy.platform.auth.rbac import Permission, RoleCode, StaffPrincipal
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.ratelimit import RateLimitExceeded

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)
_FORBIDDEN = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def _verifier(request: Request) -> OidcVerifier:
    return request.app.state.verifier  # type: ignore[no-any-return]


def get_principal(request: Request) -> StaffPrincipal:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 8192:
        raise _UNAUTHENTICATED
    try:
        claims = _verifier(request).verify(token)
    except InvalidTokenError:
        raise _UNAUTHENTICATED from None
    try:  # before any DB work, so a flood never reaches the connection pool
        request.app.state.rate_limiter.hit(
            request.app.state.staff_limit, f"{claims['iss']}|{claims['sub']}"
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too Many Requests",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None

    with request.app.state.app_engine.connect() as conn:
        row = conn.execute(
            text("SELECT tenant_id, user_id, roles FROM resolve_staff_principal(:iss, :sub)"),
            {"iss": claims["iss"], "sub": claims["sub"]},
        ).first()
    if row is None:
        raise _FORBIDDEN  # authenticated with the IdP but not provisioned in any tenant
    roles = frozenset(RoleCode(r) for r in row.roles or [] if r in RoleCode.__members__)
    return StaffPrincipal(
        user_id=row.user_id, tenant_id=row.tenant_id, subject=claims["sub"], roles=roles
    )


class Requires:
    """Route dependency that enforces one permission. Its presence is checked by tests."""

    def __init__(self, permission: Permission) -> None:
        self.permission = permission

    def __call__(
        self, principal: Annotated[StaffPrincipal, Depends(get_principal)]
    ) -> StaffPrincipal:
        if not principal.has(self.permission):
            raise _FORBIDDEN
        return principal


class Public:
    """Explicit marker for unauthenticated routes. Its presence is checked by tests."""

    def __call__(self) -> None:
        return None


def get_tenant_db(
    request: Request, principal: Annotated[StaffPrincipal, Depends(get_principal)]
) -> Iterator[Session]:
    with tenant_session(request.app.state.app_engine, TenantContext(principal.tenant_id)) as s:
        yield s


# ---------- Public (Data Principal) routes, reachable only through the web BFF --------


class InternalBff:
    """Route dependency: caller must be the web BFF (shared service credential).

    Public intake is unauthenticated for the Data Principal, but the API itself is never
    browser-facing. The BFF enforces CSRF and forwards the client IP for rate limiting.
    """

    def __call__(self, request: Request) -> None:
        supplied = request.headers.get("x-internal-auth", "")
        expected = request.app.state.settings.bff_shared_secret.get_secret_value()
        if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise _UNAUTHENTICATED


def client_ip(request: Request) -> str:
    """Client IP as forwarded by the (authenticated) BFF; only used for rate limiting."""
    raw = request.headers.get("x-client-ip", "")[:64]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "unknown"


class DataPrincipalSession:
    """Route dependency: a live DP tracking session bound to exactly one request."""

    def __call__(
        self, request: Request, _bff: Annotated[None, Depends(InternalBff())]
    ) -> DataPrincipalPrincipal:
        token = request.headers.get("x-dp-session", "")
        if not token or len(token) > 128:
            raise _UNAUTHENTICATED
        with request.app.state.app_engine.connect() as conn:
            row = conn.execute(
                text("SELECT tenant_id, request_id, session_id FROM resolve_dp_session(:h)"),
                {"h": dp_session.token_hash(token)},
            ).first()
        if row is None:
            raise _UNAUTHENTICATED
        return DataPrincipalPrincipal(row.tenant_id, row.request_id, row.session_id)
