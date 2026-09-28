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


GUARDS: dict[str, Guard] = {
    "no_unresolved_manual_review": _not_implemented("M4"),
    "approval_valid_for_version": _not_implemented("M5"),
    "all_fulfilment_tasks_terminal": _not_implemented("M6"),
}
