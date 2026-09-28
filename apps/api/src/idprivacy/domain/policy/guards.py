"""Named workflow guards referenced by policy packs (ADR-0005).

Packs stay declarative: they name guards, and the platform implements them. A guard
whose milestone hasn't landed yet fails closed, so its transition is refused.
"""

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from idprivacy.platform.models import PrivacyRequest


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reason: str = ""


Guard = Callable[[Session, PrivacyRequest], GuardResult]


def _not_implemented(milestone: str) -> Guard:
    def guard(_session: Session, _request: PrivacyRequest) -> GuardResult:
        return GuardResult(False, f"guard not implemented until {milestone}")

    return guard


def _no_unresolved_manual_review(session: Session, request: PrivacyRequest) -> GuardResult:
    from idprivacy.domain.retention.service import unresolved_manual_reviews

    pending = unresolved_manual_reviews(session, request.id)
    if pending:
        return GuardResult(False, f"{pending} record(s) still need a manual-review decision")
    return GuardResult(True)


GUARDS: dict[str, Guard] = {
    "no_unresolved_manual_review": _no_unresolved_manual_review,
    "approval_valid_for_version": _not_implemented("M5"),
    "all_fulfilment_tasks_terminal": _not_implemented("M6"),
}
