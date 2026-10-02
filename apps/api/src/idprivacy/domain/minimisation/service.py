"""Post-closure minimisation (decision D-12).

Once a case has been closed for longer than its pack's ``post_closure_retention_days``,
the platform shreds what could identify the requester: the encrypted name, submitted
and resolved identifiers, request details, blind indexes, open tracking sessions and any
disclosure or report blobs still stored. Each value has its own data key, so deleting
the ciphertext is the shred.

What stays is what the evidence needs and can't name a person without the source
system: ids, dates, rights, record pointers, decisions, approvals, verification results,
the evidence package (masked identifiers only) and the audit chain.

A legal hold on the case, the data principal, or a connector or record type the case
touched blocks minimisation until it is released.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.policy.model import DEFAULT_POST_CLOSURE_RETENTION_DAYS
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor
from idprivacy.platform.models import (
    AccessReport,
    DataMatch,
    DataPrincipal,
    DisclosureExport,
    DpSession,
    LegalHold,
    PrivacyRequest,
    RequestIdentifier,
    RequestRight,
)
from idprivacy.platform.storage import BlobStore

ACTOR = SystemActor("system:minimisation")


def _grace(session: Session, registry: PolicyRegistry, request: PrivacyRequest) -> timedelta:
    if request.policy_pack_id is None:  # closed before a pack was pinned
        return timedelta(days=DEFAULT_POST_CLOSURE_RETENTION_DAYS)
    days = registry.by_id(session, request.policy_pack_id).pack.post_closure_retention_days
    return timedelta(days=days)


def _held(session: Session, request: PrivacyRequest) -> bool:
    candidates = {("CASE", str(request.id)), ("DATA_PRINCIPAL", str(request.data_principal_id))}
    for connector_id, record_type in session.execute(
        select(DataMatch.connector_id, DataMatch.record_type)
        .where(DataMatch.request_id == request.id)
        .distinct()
    ):
        candidates |= {("CONNECTOR", connector_id), ("RECORD_TYPE", record_type)}
    holds = session.execute(
        select(LegalHold.scope, LegalHold.scope_ref).where(LegalHold.released_at.is_(None))
    )
    return any((scope, ref) in candidates for scope, ref in holds)


def _minimise(session: Session, request: PrivacyRequest, store: BlobStore, now: datetime) -> None:
    request.enc_full_name = request.enc_submitted_identifiers = None
    request.minimised_at = now
    session.execute(
        update(RequestRight).where(RequestRight.request_id == request.id).values(enc_details=None)
    )
    identifiers: int = session.execute(
        delete(RequestIdentifier).where(RequestIdentifier.request_id == request.id)
    ).rowcount  # type: ignore[attr-defined]
    session.execute(
        update(DpSession)
        .where(DpSession.request_id == request.id, DpSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    blobs = 0
    for export in session.execute(
        select(DisclosureExport).where(
            DisclosureExport.request_id == request.id,
            DisclosureExport.object_key.is_not(None),
            DisclosureExport.purged_at.is_(None),
        )
    ).scalars():
        assert export.object_key is not None
        store.delete(export.object_key)
        export.purged_at = now
        blobs += 1
    for report in session.execute(
        select(AccessReport).where(
            AccessReport.request_id == request.id, AccessReport.purged_at.is_(None)
        )
    ).scalars():
        store.delete(report.json_key)
        store.delete(report.html_key)
        report.purged_at = now
        blobs += 2
    session.flush()

    # The data principal row is shared by all of that person's requests: shred it only
    # when none of them still needs it.
    principal_shredded = False
    still_needed = session.execute(
        select(PrivacyRequest.id).where(
            PrivacyRequest.data_principal_id == request.data_principal_id,
            PrivacyRequest.minimised_at.is_(None),
        )
    ).first()
    if still_needed is None:
        session.execute(
            update(DataPrincipal)
            .where(DataPrincipal.id == request.data_principal_id)
            .values(enc_identifiers=None, bidx_email=None, bidx_phone=None, minimised_at=now)
        )
        principal_shredded = True

    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR.ref,
        action="request.minimised",
        object_type="privacy_request",
        object_id=request.id,
        details={
            # Not "identifiers_*": audit redaction blanks any key naming identifiers.
            "resolved_ids_deleted": identifiers,
            "blobs_deleted": blobs,
            "principal_shredded": principal_shredded,
        },
    )


def minimise_due(
    session: Session, *, registry: PolicyRegistry, store: BlobStore, now: datetime | None = None
) -> tuple[int, int]:
    """Minimise every due case in the session's tenant. Returns (minimised, held back)."""
    now = now or datetime.now(UTC)
    closed = (
        session.execute(
            select(PrivacyRequest)
            .where(PrivacyRequest.closed_at.is_not(None), PrivacyRequest.minimised_at.is_(None))
            .order_by(PrivacyRequest.closed_at)
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )
    done = held = 0
    for request in closed:
        assert request.closed_at is not None
        if request.closed_at + _grace(session, registry, request) > now:
            continue
        if _held(session, request):
            held += 1
            continue
        _minimise(session, request, store, now)
        done += 1
    return done, held
