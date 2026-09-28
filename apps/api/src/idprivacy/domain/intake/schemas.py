"""Allowlist schemas for public intake (threat model T-17, T-24)."""

import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from pydantic.networks import validate_email

E164 = re.compile(r"^\+[1-9]\d{7,14}$", re.ASCII)  # ASCII: \d matches all Unicode digits


class RightCode(StrEnum):
    ERASURE = "ERASURE"
    ACCESS = "ACCESS"
    CORRECTION = "CORRECTION"
    CONSENT_WITHDRAWAL = "CONSENT_WITHDRAWAL"
    GRIEVANCE = "GRIEVANCE"
    NOMINATION = "NOMINATION"


def _no_control_chars(value: str) -> str:
    if any(unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t" for ch in value):
        raise ValueError("control characters are not allowed")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class Contact(_Strict):
    channel: Literal["EMAIL", "SMS"]
    value: Annotated[str, StringConstraints(min_length=3, max_length=254)]

    @model_validator(mode="after")
    def _validate_value(self) -> Self:
        if self.channel == "EMAIL":
            validate_email(self.value)  # raises on an invalid address
        elif not E164.match(self.value):
            raise ValueError("phone number must be in E.164 format, e.g. +919876543210")
        return self

    def normalised(self) -> str:
        return self.value.lower() if self.channel == "EMAIL" else self.value


class AdditionalIdentifier(_Strict):
    type: Literal["CUSTOMER_ID"]
    value: Annotated[
        str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    ]


class ErasureRequestCreate(_Strict):
    intake_slug: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{3,40}$")] = Field(
        alias="intakeSlug"
    )
    rights: Annotated[list[RightCode], Field(min_length=1, max_length=1)]
    full_name: Annotated[str, StringConstraints(min_length=1, max_length=200)] = Field(
        alias="fullName"
    )
    contact: Contact
    additional_identifiers: Annotated[list[AdditionalIdentifier], Field(max_length=5)] = Field(
        default_factory=list, alias="additionalIdentifiers"
    )
    details: Annotated[str, StringConstraints(max_length=2000)] | None = None
    residency_claim: Literal["IN", "OTHER", "UNKNOWN"] = Field(
        default="UNKNOWN", alias="residencyClaim"
    )
    consent_to_process: Literal[True] = Field(alias="consentToProcess")

    model_config = ConfigDict(
        extra="forbid", str_strip_whitespace=True, frozen=True, populate_by_name=False
    )

    @model_validator(mode="after")
    def _text_hygiene(self) -> Self:
        _no_control_chars(self.full_name)
        if self.details:
            _no_control_chars(self.details)
        return self


class _Camel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)


class ErasureRequestAccepted(_Camel):
    display_id: str = Field(alias="displayId")
    challenge_id: str = Field(alias="challengeId")
    expires_at: datetime = Field(alias="expiresAt")
    destination_hint: str = Field(alias="destinationHint")


class OtpConfirm(_Strict):
    code: Annotated[str, StringConstraints(pattern=r"^[0-9]{6}$")]


class OtpConfirmed(_Camel):
    session_token: str = Field(alias="sessionToken")
    session_expires_at: datetime = Field(alias="sessionExpiresAt")


class OtpResent(_Camel):
    expires_at: datetime = Field(alias="expiresAt")


class PublicCaseStatus(_Camel):
    display_id: str = Field(alias="displayId")
    status: Literal[
        "Verifying", "In progress", "Completed", "Closed", "Cancelled", "Verification failed"
    ]
    submitted_at: datetime = Field(alias="submittedAt")
    due_at: datetime | None = Field(default=None, alias="dueAt")
    completion_response: str | None = Field(default=None, alias="completionResponse")
    can_cancel: bool = Field(alias="canCancel")
