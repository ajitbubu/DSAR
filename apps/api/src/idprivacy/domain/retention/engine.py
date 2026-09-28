"""Pure retention-rule evaluation (M4). Rules come from the pinned policy pack."""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from idprivacy.domain.policy.model import PolicyPack, RetentionDecisionCode, RetentionMatch

NO_RULE = "no-rule-matched"


@dataclass(frozen=True)
class MatchFacts:
    record_type: str
    data_categories: frozenset[str]
    identifier_assurance: Literal["VERIFIED", "CLAIMED"]
    legal_hold_id: UUID | None


@dataclass(frozen=True)
class Outcome:
    decision: RetentionDecisionCode
    rule_id: str
    exception_code: str | None
    legal_hold_id: UUID | None


def _applies(when: RetentionMatch, facts: MatchFacts) -> bool:
    if when.legal_hold is not None and when.legal_hold != (facts.legal_hold_id is not None):
        return False
    if (
        when.identifier_assurance is not None
        and when.identifier_assurance != facts.identifier_assurance
    ):
        return False
    if when.data_categories_any is not None and not facts.data_categories.intersection(
        when.data_categories_any
    ):
        return False
    if when.record_types_any is not None and facts.record_type not in when.record_types_any:
        return False
    return True


def evaluate(pack: PolicyPack, facts: MatchFacts) -> Outcome:
    """First matching rule wins. With no match, fail safe to MANUAL_REVIEW, never DELETE."""
    for rule in pack.retention_rules:
        if _applies(rule.when, facts):
            return Outcome(
                rule.decision,
                rule.id,
                rule.exception_code,
                facts.legal_hold_id if rule.when.legal_hold else None,
            )
    return Outcome(RetentionDecisionCode.MANUAL_REVIEW, NO_RULE, None, None)
