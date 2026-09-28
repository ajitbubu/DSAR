"""The audit events that belong to one case: the case itself and everything under it."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.platform.models import (
    AuditEvent,
    DataMatch,
    EvidenceArtifact,
    FulfilmentTask,
    IdentityVerification,
)


def case_events(session: Session, request_id: UUID) -> list[AuditEvent]:
    related: set[UUID] = {request_id}
    for model, col in (
        (DataMatch, DataMatch.request_id),
        (FulfilmentTask, FulfilmentTask.request_id),
        (IdentityVerification, IdentityVerification.request_id),
        (EvidenceArtifact, EvidenceArtifact.request_id),
    ):
        related |= set(session.execute(select(model.id).where(col == request_id)).scalars())
    return list(
        session.execute(
            select(AuditEvent).where(AuditEvent.object_id.in_(related)).order_by(AuditEvent.seq)
        ).scalars()
    )
