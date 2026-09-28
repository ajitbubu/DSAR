"""Identity resolution: submitted identifiers → canonical identifier set (M2).

Each identifier carries an assurance level:
- VERIFIED: the requester proved control of it (the OTP destination).
- CLAIMED: typed into the form and unproven (e.g. a customer ID).

Normalisation is deliberately conservative. Two strings are merged only if every mail
or phone system would treat them as the same identifier. Provider-specific tricks
(e.g. ignoring dots or "+tags" in Gmail addresses) aren't applied, because they could
link someone else's data to the requester.
"""

import json
import unicodedata
from dataclasses import dataclass
from typing import Literal

from pydantic.networks import validate_email
from sqlalchemy.orm import Session

from idprivacy.domain.intake import service as intake
from idprivacy.platform.crypto import FieldCipher, KeyProvider, blind_index
from idprivacy.platform.models import IdentityVerification, PrivacyRequest, RequestIdentifier

IdentifierType = Literal["EMAIL", "PHONE", "CUSTOMER_ID"]
CTX_REQUEST_IDENTIFIER = "request_identifier.value"


class NormalisationError(ValueError):
    pass


def normalise_email(raw: str) -> str:
    """Lower-case, NFC, IDNA (punycode) domain. The local part is kept intact otherwise."""
    value = unicodedata.normalize("NFC", raw.strip())
    try:
        _, email = validate_email(value)
    except Exception as exc:  # PydanticCustomError
        raise NormalisationError("invalid email address") from exc
    local, _, domain = email.rpartition("@")
    domain = domain.lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalisationError("invalid email domain") from exc
    return f"{local.lower()}@{domain}"


def normalise_phone(raw: str) -> str:
    """E.164 only: '+' then 8–15 digits. Spaces, dashes, dots and brackets are dropped."""
    compact = "".join(ch for ch in raw.strip() if ch not in " -.() ")
    digits = compact[1:]
    # isascii() matters: str.isdigit() also accepts e.g. Arabic-Indic or fullwidth digits.
    if not (
        compact.startswith("+")
        and digits.isascii()
        and digits.isdigit()
        and 8 <= len(digits) <= 15
        and digits[0] != "0"
    ):
        raise NormalisationError("phone number must be E.164")
    return compact


def normalise_customer_id(raw: str) -> str:
    value = raw.strip().upper()
    if (
        not value
        or len(value) > 64
        or not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in value)
    ):
        raise NormalisationError("invalid customer id")
    return value


_NORMALISERS = {
    "EMAIL": normalise_email,
    "PHONE": normalise_phone,
    "CUSTOMER_ID": normalise_customer_id,
}


@dataclass(frozen=True)
class CanonicalIdentifier:
    type: IdentifierType
    value: str
    assurance: Literal["VERIFIED", "CLAIMED"]
    source: Literal["OTP", "FORM"]


def canonicalise(
    contact_channel: str, contact_value: str, verified: bool, additional: list[dict[str, str]]
) -> list[CanonicalIdentifier]:
    """Build the de-duplicated canonical set. The strongest assurance wins on duplicates."""
    contact_type: IdentifierType = "EMAIL" if contact_channel == "EMAIL" else "PHONE"
    found: dict[tuple[str, str], CanonicalIdentifier] = {}
    candidates = [
        CanonicalIdentifier(
            contact_type,
            _NORMALISERS[contact_type](contact_value),
            "VERIFIED" if verified else "CLAIMED",
            "OTP" if verified else "FORM",
        )
    ]
    for item in additional:
        if item.get("type") == "CUSTOMER_ID":
            candidates.append(
                CanonicalIdentifier(
                    "CUSTOMER_ID", normalise_customer_id(item["value"]), "CLAIMED", "FORM"
                )
            )
    for c in candidates:
        key = (c.type, c.value)
        if key not in found or (c.assurance == "VERIFIED" and found[key].assurance != "VERIFIED"):
            found[key] = c
    return list(found.values())


def resolve(
    session: Session, *, request: PrivacyRequest, keys: KeyProvider, cipher: FieldCipher
) -> list[CanonicalIdentifier]:
    """Persist the canonical set for a verified request. Idempotent per request."""
    submitted = json.loads(
        cipher.decrypt(request.tenant_id, intake.CTX_SUBMITTED, request.enc_submitted_identifiers)
    )
    verified = (
        session.query(IdentityVerification)
        .filter(
            IdentityVerification.request_id == request.id, IdentityVerification.status == "VERIFIED"
        )
        .first()
        is not None
    )
    identifiers = canonicalise(
        submitted["contact"]["channel"],
        submitted["contact"]["value"],
        verified,
        submitted.get("additional", []),
    )
    existing = {
        (r.type, r.bidx)
        for r in session.query(RequestIdentifier).filter(RequestIdentifier.request_id == request.id)
    }
    for ident in identifiers:
        bidx = blind_index(keys, request.tenant_id, ident.type.lower(), ident.value)
        if (ident.type, bidx) in existing:
            continue
        session.add(
            RequestIdentifier(
                tenant_id=request.tenant_id,
                request_id=request.id,
                type=ident.type,
                bidx=bidx,
                enc_value=cipher.encrypt(request.tenant_id, CTX_REQUEST_IDENTIFIER, ident.value),
                assurance=ident.assurance,
                source=ident.source,
            )
        )
    session.flush()
    return identifiers
