"""HTTP hardening: request-size limits and RFC 9457 problem responses.

Validation errors never echo the submitted input back (it may be personal data).
"""

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

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = self.max_bytes + 1
                if declared > self.max_bytes:
                    await problem(413, "Payload Too Large")(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
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
