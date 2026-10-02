"""Typed policy-pack model (ADR-0005). This is the single source of the pack schema.

``packages/policy-packs/schema/policy-pack.schema.json`` is generated from it for pack
authors (``make policy-schema``) and checked for drift in tests.

Semantic checks run at load time: every state is a known case status, every guard and
permission exists in the platform catalogue, every right points at a defined workflow,
and retention rules only use known exception codes.
"""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.intake.schemas import RightCode
from idprivacy.domain.policy.guards import GUARDS
from idprivacy.platform.auth.rbac import Permission

Code = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,31}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,31}$")]
SemVer = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
Text = Annotated[str, StringConstraints(min_length=1, max_length=500)]
VerificationMethod = Literal["OTP_EMAIL", "OTP_SMS"]
Assurance = Literal["VERIFIED", "CLAIMED"]
RecordType = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.]{1,63}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RetentionDecisionCode(StrEnum):
    DELETE = "DELETE"
    RETAIN = "RETAIN"
    RESTRICT = "RESTRICT"
    ANONYMIZE = "ANONYMIZE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class ApplicabilityCondition(_Strict):
    """All fields present in one condition must match (AND)."""

    tenant_region: list[Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]] | None = None
    requester_residency: list[Literal["IN", "OTHER", "UNKNOWN"]] | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if self.tenant_region is None and self.requester_residency is None:
            raise ValueError("an applicability condition needs at least one field")
        return self


class Applicability(_Strict):
    """The pack applies when any condition matches (OR of ANDs)."""

    any_of: Annotated[list[ApplicabilityCondition], Field(min_length=1)]


class Right(_Strict):
    title: Text
    reference: Text | None = None
    executable: bool
    workflow: Slug
    accepted_verification: Annotated[list[VerificationMethod], Field(min_length=1)]


class SlaRule(_Strict):
    # None means "not yet set": response values need legal sign-off (open decision D-9).
    response_days: Annotated[int, Field(ge=1, le=365)] | None
    clock_start: Literal["SUBMITTED", "VERIFIED"]
    validated: bool

    @model_validator(mode="after")
    def _validated_needs_value(self) -> Self:
        if self.validated and self.response_days is None:
            raise ValueError("a validated SLA rule must set response_days")
        return self


class IdentityResolution(_Strict):
    discovery_assurance: Annotated[list[Assurance], Field(min_length=1)]


class ExceptionCode(_Strict):
    code: Code
    label: Text
    reference: Text | None = None
    requires_reason: bool = True


class RetentionMatch(_Strict):
    legal_hold: bool | None = None
    identifier_assurance: Assurance | None = None
    data_categories_any: list[Slug] | None = None
    record_types_any: (
        list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.]{1,63}$")]] | None
    ) = None


class RetentionRule(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,63}$")]
    when: RetentionMatch
    decision: RetentionDecisionCode
    exception_code: Code | None = None

    @model_validator(mode="after")
    def _retain_needs_exception(self) -> Self:
        if self.decision == RetentionDecisionCode.RETAIN and self.exception_code is None:
            raise ValueError(f"rule {self.id}: RETAIN requires an exception_code")
        return self


class Transition(_Strict):
    event: Code
    from_: Annotated[list[CaseStatus], Field(min_length=1, alias="from")]
    to: CaseStatus
    actor: Literal["SYSTEM", "USER"]
    permission: Permission | None = None
    guards: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.actor == "USER" and self.permission is None:
            raise ValueError(f"{self.event}: USER transitions must declare a permission")
        if self.actor == "SYSTEM" and self.permission is not None:
            raise ValueError(f"{self.event}: SYSTEM transitions must not declare a permission")
        unknown = [g for g in self.guards if g not in GUARDS]
        if unknown:
            raise ValueError(f"{self.event}: unknown guards {unknown}")
        return self


class Workflow(_Strict):
    entry_state: CaseStatus
    transitions: Annotated[list[Transition], Field(min_length=1)]

    @model_validator(mode="after")
    def _deterministic(self) -> Self:
        seen: set[tuple[str, CaseStatus]] = set()
        for t in self.transitions:
            for state in t.from_:
                key = (t.event, state)
                if key in seen:
                    raise ValueError(f"duplicate transition {t.event} from {state}")
                seen.add(key)
        return self

    def find(self, event: str, current: CaseStatus) -> Transition | None:
        return next((t for t in self.transitions if t.event == event and current in t.from_), None)


# How long a closed case keeps the requester's identifiers before they are shredded
# (decision D-12). Applies to packs that don't set it and to cases without a pack.
DEFAULT_POST_CLOSURE_RETENTION_DAYS = 30


class PolicyPack(_Strict):
    code: Code
    version: SemVer
    title: Text
    legal_review: Literal["PENDING", "APPROVED"]
    applicability: Applicability
    rights: dict[RightCode, Right]
    sla: dict[RightCode, SlaRule]
    identity_resolution: IdentityResolution
    exception_codes: Annotated[list[ExceptionCode], Field(min_length=1)]
    retention_rules: Annotated[list[RetentionRule], Field(min_length=1)]
    workflows: dict[Slug, Workflow]
    post_closure_retention_days: Annotated[int, Field(ge=0, le=3650)] = (
        DEFAULT_POST_CLOSURE_RETENTION_DAYS
    )

    @model_validator(mode="after")
    def _cross_references(self) -> Self:
        missing_rights = set(RightCode) - set(self.rights)
        if missing_rights:
            raise ValueError(f"rights catalogue incomplete: {sorted(missing_rights)}")
        if set(self.sla) != set(self.rights):
            raise ValueError("every right needs exactly one SLA rule")
        for code, right in self.rights.items():
            if right.workflow not in self.workflows:
                raise ValueError(f"right {code} references unknown workflow {right.workflow!r}")
        known = {e.code for e in self.exception_codes}
        if len(known) != len(self.exception_codes):
            raise ValueError("duplicate exception codes")
        for rule in self.retention_rules:
            if rule.exception_code and rule.exception_code not in known:
                raise ValueError(f"rule {rule.id} uses unknown exception code")
        return self

    @property
    def ref(self) -> str:
        return f"{self.code}@{self.version}"
