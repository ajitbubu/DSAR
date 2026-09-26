"""Append-only, per-tenant hash-chained audit log (ADR-0004).

``append`` must be called inside the same transaction as the change it records.
The per-tenant head row is locked ``FOR UPDATE`` so appends are serialised per tenant.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from idprivacy.platform.logging import redact
from idprivacy.platform.models import AuditEvent, TenantAuditHead

GENESIS_HASH = "0" * 64
ActorType = Literal["USER", "DATA_PRINCIPAL", "SYSTEM", "CONNECTOR"]


def _canonical(
    tenant_id: UUID,
    seq: int,
    occurred_at: datetime,
    actor_type: str,
    actor_ref: str,
    action: str,
    object_type: str,
    object_id: UUID | None,
    details: dict[str, Any],
) -> bytes:
    body = {
        "tenant_id": str(tenant_id),
        "seq": seq,
        "occurred_at": occurred_at.astimezone(UTC).isoformat(),
        "actor_type": actor_type,
        "actor_ref": actor_ref,
        "action": action,
        "object_type": object_type,
        "object_id": str(object_id) if object_id else None,
        "details": details,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _chain(prev_hash: str, canonical: bytes) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical).hexdigest()


def append(
    session: Session,
    *,
    tenant_id: UUID,
    actor_type: ActorType,
    actor_ref: str,
    action: str,
    object_type: str,
    object_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    session.execute(
        pg_insert(TenantAuditHead)
        .values(tenant_id=tenant_id, last_seq=0, last_hash=GENESIS_HASH)
        .on_conflict_do_nothing(index_elements=["tenant_id"])
    )
    head = session.execute(
        select(TenantAuditHead).where(TenantAuditHead.tenant_id == tenant_id).with_for_update()
    ).scalar_one()

    safe_details: dict[str, Any] = redact(details or {})
    seq = head.last_seq + 1
    occurred_at = datetime.now(UTC)
    digest = _chain(
        head.last_hash,
        _canonical(
            tenant_id,
            seq,
            occurred_at,
            actor_type,
            actor_ref,
            action,
            object_type,
            object_id,
            safe_details,
        ),
    )
    event = AuditEvent(
        tenant_id=tenant_id,
        seq=seq,
        occurred_at=occurred_at,
        actor_type=actor_type,
        actor_ref=actor_ref,
        action=action,
        object_type=object_type,
        object_id=object_id,
        details=safe_details,
        prev_hash=head.last_hash,
        hash=digest,
    )
    session.add(event)
    head.last_seq, head.last_hash = seq, digest
    session.flush()
    return event


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    events_checked: int
    first_broken_seq: int | None


def verify_chain(session: Session, tenant_id: UUID) -> ChainVerification:
    prev_hash, expected_seq, checked = GENESIS_HASH, 1, 0
    rows = session.execute(
        select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.seq)
    ).scalars()
    for ev in rows:
        recomputed = _chain(
            prev_hash,
            _canonical(
                ev.tenant_id,
                ev.seq,
                ev.occurred_at,
                ev.actor_type,
                ev.actor_ref,
                ev.action,
                ev.object_type,
                ev.object_id,
                ev.details,
            ),
        )
        if ev.seq != expected_seq or ev.prev_hash != prev_hash or ev.hash != recomputed:
            return ChainVerification(False, checked, ev.seq)
        prev_hash, expected_seq, checked = ev.hash, expected_seq + 1, checked + 1

    head = session.get(TenantAuditHead, tenant_id)
    if head is not None and (head.last_seq != checked or head.last_hash != prev_hash):
        return ChainVerification(False, checked, checked + 1)
    return ChainVerification(True, checked, None)
