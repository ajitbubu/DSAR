"""Jurisdiction decision: which enabled policy pack governs a request (M2).

Pure and regulation-agnostic. Packs declare their own applicability. The tenant chooses
which pack versions are enabled and in what order. Nothing here names a regulation.
"""

from dataclasses import dataclass
from typing import Literal

from idprivacy.domain.policy.model import ApplicabilityCondition, PolicyPack
from idprivacy.domain.policy.registry import PublishedPack


@dataclass(frozen=True)
class JurisdictionInputs:
    tenant_region: str | None
    requester_residency: Literal["IN", "OTHER", "UNKNOWN"]
    right_code: str
    verification_method: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "tenant_region": self.tenant_region,
            "requester_residency": self.requester_residency,
            "right_code": self.right_code,
            "verification_method": self.verification_method,
        }


@dataclass(frozen=True)
class Decision:
    outcome: Literal["APPLICABLE", "NO_APPLICABLE_PACK"]
    pack: PublishedPack | None
    executable: bool
    workflow_code: str | None
    rationale: str


def _matches(cond: ApplicabilityCondition, inputs: JurisdictionInputs) -> list[str] | None:
    """Return the matched clauses, or None if the condition doesn't hold."""
    matched: list[str] = []
    if cond.tenant_region is not None:
        if inputs.tenant_region not in cond.tenant_region:
            return None
        matched.append(f"tenant_region={inputs.tenant_region}")
    if cond.requester_residency is not None:
        if inputs.requester_residency not in cond.requester_residency:
            return None
        matched.append(f"requester_residency={inputs.requester_residency}")
    return matched


def applies(pack: PolicyPack, inputs: JurisdictionInputs) -> list[str] | None:
    for cond in pack.applicability.any_of:
        matched = _matches(cond, inputs)
        if matched is not None:
            return matched
    return None


def decide(candidates: list[PublishedPack], inputs: JurisdictionInputs) -> Decision:
    """``candidates`` are the tenant's enabled packs, already in priority order."""
    for published in candidates:
        pack = published.pack
        matched = applies(pack, inputs)
        if matched is None:
            continue
        right = pack.rights.get(inputs.right_code)  # type: ignore[call-overload]
        basis = f"{pack.ref} applies ({', '.join(matched)})"
        if right is None:
            return Decision(
                "APPLICABLE",
                published,
                False,
                None,
                f"{basis}; right {inputs.right_code} not in its catalogue",
            )
        if inputs.verification_method not in right.accepted_verification:
            return Decision(
                "APPLICABLE",
                published,
                False,
                None,
                f"{basis}; verification {inputs.verification_method} is not "
                f"accepted for {inputs.right_code}",
            )
        mode = "executable workflow" if right.executable else "manual handling (placeholder)"
        return Decision(
            "APPLICABLE",
            published,
            right.executable,
            right.workflow,
            f"{basis}; {inputs.right_code} → {right.workflow} ({mode})",
        )
    return Decision(
        "NO_APPLICABLE_PACK", None, False, None, "no enabled policy pack applies to this request"
    )
