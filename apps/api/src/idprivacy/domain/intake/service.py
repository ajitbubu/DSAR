"""Public request intake: create the case, issue the OTP challenge, audit everything."""

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.config import Settings
from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus, IntakeEvent, transition
from idprivacy.domain.identity import verification
from idprivacy.domain.identity.otp import OtpProvider
from idprivacy.domain.intake.schemas import Contact, ErasureRequestCreate
from idprivacy.platform.crypto import FieldCipher, KeyProvider, blind_index
from idprivacy.platform.models import DataPrincipal, PrivacyRequest, RequestRight

# Crockford base32 (no I, L, O, U): unambiguous when read aloud or typed.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CTX_IDENTIFIERS = "data_principal.identifiers"
CTX_SUBMITTED = "privacy_request.submitted_identifiers"
CTX_NAME = "privacy_request.full_name"
CTX_DETAILS = "request_right.details"


@dataclass(frozen=True)
class SubmitResult:
    display_id: str
    challenge_id: UUID
    expires_at: datetime
    destination_hint: str


def contact_bidx(keys: KeyProvider, tenant_id: UUID, contact: Contact) -> str:
    kind = "email" if contact.channel == "EMAIL" else "phone"
    return blind_index(keys, tenant_id, kind, contact.normalised())


def destination_hint(contact: Contact) -> str:
    value = contact.normalised()
    if contact.channel == "EMAIL":
        local, _, domain = value.partition("@")
        tld = domain.rsplit(".", 1)[-1]
        return f"{local[0]}•••@{domain[0]}•••.{tld}"
    return f"{value[:3]}•••••{value[-3:]}"


def _new_display_id(session: Session, tenant_id: UUID) -> str:
    year = datetime.now(UTC).year
    for _ in range(5):
        candidate = f"DPR-{year}-" + "".join(secrets.choice(_ALPHABET) for _ in range(6))
        exists = session.execute(
            select(PrivacyRequest.id).where(
                PrivacyRequest.tenant_id == tenant_id, PrivacyRequest.display_id == candidate
            )
        ).first()
        if exists is None:
            return candidate
    raise RuntimeError("could not allocate a display id")


def _find_or_create_principal(
    session: Session,
    *,
    keys: KeyProvider,
    cipher: FieldCipher,
    tenant_id: UUID,
    payload: ErasureRequestCreate,
) -> DataPrincipal:
    bidx = contact_bidx(keys, tenant_id, payload.contact)
    column = (
        DataPrincipal.bidx_email if payload.contact.channel == "EMAIL" else DataPrincipal.bidx_phone
    )
    existing = (
        session.execute(
            select(DataPrincipal).where(DataPrincipal.tenant_id == tenant_id, column == bidx)
        )
        .scalars()
        .first()
    )
    if existing is not None:
        return existing
    identifiers = {payload.contact.channel.lower(): payload.contact.normalised()}
    principal = DataPrincipal(
        tenant_id=tenant_id,
        enc_identifiers=cipher.encrypt(tenant_id, CTX_IDENTIFIERS, json.dumps(identifiers)),
        bidx_email=bidx if payload.contact.channel == "EMAIL" else None,
        bidx_phone=bidx if payload.contact.channel == "SMS" else None,
    )
    session.add(principal)
    session.flush()
    return principal


def submit(
    session: Session,
    *,
    tenant_id: UUID,
    payload: ErasureRequestCreate,
    keys: KeyProvider,
    cipher: FieldCipher,
    provider: OtpProvider,
    settings: Settings,
) -> SubmitResult:
    principal = _find_or_create_principal(
        session, keys=keys, cipher=cipher, tenant_id=tenant_id, payload=payload
    )
    submitted = {
        "contact": {"channel": payload.contact.channel, "value": payload.contact.normalised()},
        "additional": [i.model_dump() for i in payload.additional_identifiers],
    }
    request = PrivacyRequest(
        tenant_id=tenant_id,
        display_id=_new_display_id(session, tenant_id),
        data_principal_id=principal.id,
        status=CaseStatus.SUBMITTED,
        channel="WEB",
        version=1,
        enc_full_name=cipher.encrypt(tenant_id, CTX_NAME, payload.full_name),
        enc_submitted_identifiers=cipher.encrypt(tenant_id, CTX_SUBMITTED, json.dumps(submitted)),
        residency_claim=payload.residency_claim,
    )
    session.add(request)
    session.flush()
    for right in payload.rights:
        session.add(
            RequestRight(
                tenant_id=tenant_id,
                request_id=request.id,
                right_code=right.value,
                enc_details=(
                    cipher.encrypt(tenant_id, CTX_DETAILS, payload.details)
                    if payload.details
                    else None
                ),
            )
        )
    audit.append(
        session,
        tenant_id=tenant_id,
        actor_type="DATA_PRINCIPAL",
        actor_ref=f"data_principal:{request.id}",
        action="request.submitted",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "rights": [r.value for r in payload.rights],
            "channel": "WEB",
            "residency_claim": payload.residency_claim,
        },
    )
    challenge = verification.issue(
        session,
        keys=keys,
        provider=provider,
        settings=settings,
        request=request,
        channel=payload.contact.channel,
        destination=payload.contact.normalised(),
    )
    transition(
        session,
        request,
        IntakeEvent.ISSUE_CHALLENGE,
        actor_type="SYSTEM",
        actor_ref="system:intake",
    )
    return SubmitResult(
        request.display_id, challenge.id, challenge.expires_at, destination_hint(payload.contact)
    )


def contact_for_request(cipher: FieldCipher, request: PrivacyRequest) -> tuple[str, str]:
    """Return ``(channel, destination)`` for resending an OTP."""
    data = json.loads(
        cipher.decrypt(request.tenant_id, CTX_SUBMITTED, request.enc_submitted_identifiers)
    )
    return data["contact"]["channel"], data["contact"]["value"]
