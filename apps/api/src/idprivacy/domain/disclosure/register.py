"""The tenant's processing register: purposes and recipients per source system.

It answers the "who else has my data, and why" part of an access request. Entries are
append-only versions; the latest per connector is current. Who maintains it and how it
is evidenced is decision D-27 (default: the tenant admin edits it in the console).
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.platform.auth.rbac import StaffPrincipal
from idprivacy.platform.models import ConnectorConfig, ProcessingRegisterEntry


class UnknownConnector(LookupError):
    pass


def current_register(session: Session) -> dict[str, ProcessingRegisterEntry]:
    latest: dict[str, ProcessingRegisterEntry] = {}
    for row in session.execute(
        select(ProcessingRegisterEntry).order_by(
            ProcessingRegisterEntry.created_at, ProcessingRegisterEntry.id
        )
    ).scalars():
        latest[row.connector_id] = row
    return latest


@dataclass(frozen=True)
class RegisterInput:
    purposes: list[str]
    recipients: list[dict[str, str]]


def put_entry(
    session: Session,
    *,
    tenant_id: UUID,
    connector_id: str,
    data: RegisterInput,
    principal: StaffPrincipal | None,
) -> ProcessingRegisterEntry:
    if (
        session.execute(
            select(ConnectorConfig.id).where(ConnectorConfig.connector_id == connector_id)
        ).first()
        is None
    ):
        raise UnknownConnector(connector_id)
    entry = ProcessingRegisterEntry(
        tenant_id=tenant_id,
        connector_id=connector_id,
        purposes=data.purposes,
        recipients=data.recipients,
        updated_by=principal.user_id if principal else None,
    )
    session.add(entry)
    session.flush()
    audit.append(
        session,
        tenant_id=tenant_id,
        actor_type="USER" if principal else "SYSTEM",
        actor_ref=str(principal.user_id) if principal else "system:seed",
        action="processing_register.updated",
        object_type="processing_register_entry",
        object_id=entry.id,
        details={
            "connector_id": connector_id,
            "purposes": len(data.purposes),
            "recipients": len(data.recipients),
        },
    )
    return entry
