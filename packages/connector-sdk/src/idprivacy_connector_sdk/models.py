"""Wire models shared by the platform and every connector (ADR-0006).

Connector output is untrusted (threat model T-13). Every model forbids unknown fields
and bounds sizes. Match metadata may carry only non-personal attributes, and values
that look like emails or phone numbers are rejected outright.
"""

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

MAX_PAGE_SIZE = 100
MAX_IDENTIFIERS = 20

_EMAIL_LIKE = re.compile(r"[^\s@]+@[^\s@]+\.[^\W\d_]{2,}")
_PHONE_LIKE = re.compile(r"\+?\d[\d\s().-]{7,}\d")

RecordRef = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")]
RecordType = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.]{1,63}$")]
Category = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,31}$")]
AttrKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
IdempotencyKey = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ReceiptId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{8,64}$")]
AttrValue = bool | int | Annotated[str, StringConstraints(max_length=64)] | None


class _Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IdentifierType(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CUSTOMER_ID = "CUSTOMER_ID"


class Action(StrEnum):
    DELETE = "DELETE"
    ANONYMIZE = "ANONYMIZE"
    RESTRICT = "RESTRICT"


class Identifier(_Wire):
    type: IdentifierType
    value: Annotated[str, StringConstraints(min_length=1, max_length=254)]


class ConnectorDescriptor(_Wire):
    connector_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,39}$")]
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    record_types: Annotated[list[RecordType], Field(min_length=1, max_length=50)]
    supported_actions: Annotated[list[Action], Field(min_length=1)]
    idempotency_retention_days: Annotated[int, Field(ge=1, le=3650)]


class ConnectionStatus(_Wire):
    ok: bool
    descriptor: ConnectorDescriptor


class DiscoveryRequest(_Wire):
    identifiers: Annotated[list[Identifier], Field(min_length=1, max_length=MAX_IDENTIFIERS)]
    page_size: Annotated[int, Field(ge=1, le=MAX_PAGE_SIZE)] = 50
    page_token: Annotated[str, StringConstraints(max_length=256)] | None = None


class Match(_Wire):
    """A pointer to one record. Never the record's content."""

    source_record_ref: RecordRef
    record_type: RecordType
    data_categories: Annotated[list[Category], Field(min_length=1, max_length=20)]
    matched_on: Annotated[list[IdentifierType], Field(min_length=1, max_length=3)]
    content_fingerprint: Sha256
    attributes: Annotated[dict[AttrKey, AttrValue], Field(max_length=20)] = Field(
        default_factory=dict
    )

    @field_validator("attributes")
    @classmethod
    def _no_personal_data(cls, value: dict[str, AttrValue]) -> dict[str, AttrValue]:
        for key, item in value.items():
            if isinstance(item, str) and (_EMAIL_LIKE.search(item) or _PHONE_LIKE.search(item)):
                raise ValueError(f"attribute {key!r} looks like personal data")
        return value


class DiscoveryPage(_Wire):
    matches: Annotated[list[Match], Field(max_length=MAX_PAGE_SIZE)]
    next_page_token: Annotated[str, StringConstraints(max_length=256)] | None = None


class ActionRequest(_Wire):
    idempotency_key: IdempotencyKey
    action: Action
    source_record_ref: RecordRef


class ActionResult(_Wire):
    idempotency_key: IdempotencyKey
    receipt_id: ReceiptId
    action: Action
    source_record_ref: RecordRef
    outcome: Literal["APPLIED", "ALREADY_ABSENT"]
    applied_at: datetime
    replayed: bool


class VerifyRequest(_Wire):
    source_record_ref: RecordRef


class VerifyResult(_Wire):
    source_record_ref: RecordRef
    observed: Literal["PRESENT", "ABSENT", "ANONYMIZED", "RESTRICTED"]


class EvidenceRequest(_Wire):
    receipt_id: ReceiptId


class EvidenceBundle(_Wire):
    receipt_id: ReceiptId
    idempotency_key: IdempotencyKey
    action: Action
    source_record_ref: RecordRef
    applied_at: datetime
    system_statement: Annotated[str, StringConstraints(max_length=500)]
    sha256: Sha256
