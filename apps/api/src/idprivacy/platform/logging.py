"""Structured JSON logging with PII redaction.

Every log record — structlog or stdlib — passes through ``redact`` before rendering.
Redaction is by key name (denylist) and by value pattern (emails, phone numbers).
"""

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import IO, Any

import structlog

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PARTS = (
    "email",
    "phone",
    "name",
    "otp",
    "code",
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "identifier",
    "address",
    "session",
)
# Keys that contain a sensitive part but are safe structural metadata.
_SAFE_KEYS = frozenset({"event", "logger", "logger_name", "level", "timestamp", "status_code"})

# The TLD must be alphabetic, so identifiers like "PACK@1.0.0" aren't mistaken for emails.
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}\b")
# Phone-like digit runs. The look-arounds exclude UUID segments and identifier fragments.
_PHONE_RE = re.compile(r"(?<![\w-])\+?\d(?:[\s-]?\d){8,14}(?![\w-])")


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    return k not in _SAFE_KEYS and any(part in k for part in _SENSITIVE_KEY_PARTS)


def redact_text(value: str) -> str:
    return _PHONE_RE.sub(REDACTED, _EMAIL_RE.sub(REDACTED, value))


def redact(value: Any) -> Any:
    """Return a redacted deep copy of ``value``."""
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if isinstance(k, str) and _is_sensitive_key(k) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    return redact(event_dict)  # type: ignore[no-any-return]


def configure_logging(level: int = logging.INFO, stream: IO[str] | None = None) -> None:
    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.format_exc_info,
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[*shared, structlog.stdlib.ExtraAdder()],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _redact_processor,
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "celery"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
