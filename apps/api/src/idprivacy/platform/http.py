"""HTTP hardening: request-size limits and RFC 9457 problem responses.

Validation errors never echo the submitted input back (it may be personal data).
"""

import re
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

PROBLEM = "application/problem+json"


def problem(
    status: int, title: str, headers: Mapping[str, str] | None = None, **extra: Any
) -> JSONResponse:
    body = {"type": "about:blank", "title": title, "status": status, **extra}
    return JSONResponse(body, status_code=status, media_type=PROBLEM, headers=headers)


class BodySizeLimitMiddleware:
    """Rejects bodies over ``max_bytes`` with 413, whether declared or streamed."""

    def __init__(
        self, app: ASGIApp, max_bytes: int, overrides: dict[str, int] | None = None
    ) -> None:
        self.app = app
        self.default_max = max_bytes
        self.overrides = [(re.compile(p), n) for p, n in (overrides or {}).items()]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = next((n for p, n in self.overrides if p.match(path)), self.default_max)
        await self._limited(scope, receive, send, limit)

    async def _limited(self, scope: Scope, receive: Receive, send: Send, limit: int) -> None:
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = limit + 1
                if declared > limit:
                    await problem(413, "Payload Too Large")(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # HTTPException passes through FastAPI's body parsing to the handlers.
                    raise StarletteHTTPException(413, "Payload Too Large")
            return message

        await self.app(scope, limited_receive, send)


def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem(exc.status_code, str(exc.detail), headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", ())), "type": e.get("type"), "msg": e.get("msg")}
            for e in exc.errors()
        ]
        return problem(422, "Unprocessable Entity", errors=errors)


_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]


class SecurityHeadersMiddleware:
    """Defence in depth: the API isn't browser-facing, but its responses stay inert if
    one is ever rendered. /v1 responses are never cached."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        no_store = scope.get("path", "").startswith("/v1/")

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for key, value in _SECURITY_HEADERS:
                    if key not in present:
                        headers.append((key, value))
                if no_store and b"cache-control" not in present:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, with_headers)
