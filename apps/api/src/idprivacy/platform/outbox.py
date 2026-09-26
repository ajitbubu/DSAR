"""Transactional outbox (ADR-0005).

Domain code calls ``enqueue`` in the same transaction as its state change. The relay
(``relay_once``) runs as the ``idp_relay`` DB role, claims unpublished rows with
``FOR UPDATE SKIP LOCKED``, publishes them, and marks them published. Delivery is
at-least-once; consumers use the outbox id as their idempotency key.

Payloads may carry only identifiers (UUID strings or ints), never personal data.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from idprivacy.platform.models import OutboxMessage

MAX_PAYLOAD_KEYS = 16


class UnsafePayloadError(ValueError):
    pass


def _validate_payload(payload: dict[str, Any]) -> dict[str, str | int]:
    if len(payload) > MAX_PAYLOAD_KEYS:
        raise UnsafePayloadError("too many payload keys")
    clean: dict[str, str | int] = {}
    for key, value in payload.items():
        if not key.endswith("_id") and key not in {"attempt", "version"}:
            raise UnsafePayloadError(f"payload key {key!r} is not an identifier field")
        if isinstance(value, UUID):
            clean[key] = str(value)
        elif isinstance(value, int) and not isinstance(value, bool):
            clean[key] = value
        elif isinstance(value, str):
            try:
                clean[key] = str(UUID(value))
            except ValueError as exc:
                raise UnsafePayloadError(f"payload value for {key!r} is not a UUID") from exc
        else:
            raise UnsafePayloadError(f"payload value for {key!r} has unsupported type")
    return clean


def enqueue(session: Session, *, tenant_id: UUID, topic: str, payload: dict[str, Any]) -> UUID:
    msg = OutboxMessage(tenant_id=tenant_id, topic=topic, payload=_validate_payload(payload))
    session.add(msg)
    session.flush()
    return msg.id


@dataclass(frozen=True)
class Envelope:
    id: UUID
    tenant_id: UUID
    topic: str
    payload: dict[str, Any]


def relay_once(relay_engine: Engine, publish: Callable[[Envelope], None], batch: int = 100) -> int:
    """Publish up to ``batch`` messages. Returns the number published."""
    factory = sessionmaker(bind=relay_engine, expire_on_commit=False)
    with factory() as session, session.begin():
        rows = (
            session.execute(
                select(OutboxMessage)
                .where(OutboxMessage.published_at.is_(None))
                .order_by(OutboxMessage.created_at)
                .limit(batch)
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )
        for row in rows:
            publish(Envelope(row.id, row.tenant_id, row.topic, dict(row.payload)))
            row.published_at = datetime.now(UTC)
        return len(rows)
