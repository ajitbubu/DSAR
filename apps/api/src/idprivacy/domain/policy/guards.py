"""Named workflow guards referenced by policy packs (ADR-0005).

Packs stay declarative: they name guards, and the platform implements them. A pack
naming an unknown guard is rejected when it loads. A guard that exists but isn't built
yet fails closed, so its transition is refused.
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


def _no_unresolved_manual_review(session: Session, request: PrivacyRequest) -> GuardResult:
    from idprivacy.domain.retention.service import unresolved_manual_reviews

    pending = unresolved_manual_reviews(session, request.id)
    if pending:
        return GuardResult(False, f"{pending} record(s) still need a manual-review decision")
    return GuardResult(True)


def _approval_valid_for_version(session: Session, request: PrivacyRequest) -> GuardResult:
    from idprivacy.domain.approvals.service import latest_approval_is_valid

    ok, reason = latest_approval_is_valid(session, request)
    return GuardResult(ok, reason)


def _all_fulfilment_tasks_terminal(session: Session, request: PrivacyRequest) -> GuardResult:
    from idprivacy.domain.fulfilment.service import all_terminal

    done, open_ = all_terminal(session, request.id)
    return GuardResult(True) if done else GuardResult(False, f"{open_} task(s) still running")


def _not_implemented_yet(milestone: str) -> Guard:
    """For guards a published pack names before the platform implements them: fail closed."""

    def guard(_session: Session, _request: PrivacyRequest) -> GuardResult:
        return GuardResult(False, f"not available until {milestone}")

    return guard


GUARDS: dict[str, Guard] = {
    "no_unresolved_manual_review": _no_unresolved_manual_review,
    "approval_valid_for_version": _approval_valid_for_version,
    "all_fulfilment_tasks_terminal": _all_fulfilment_tasks_terminal,
    # Right to Access (docs/milestones-access.md).
    "disclosure_reviewed": _not_implemented_yet("access milestone A2"),
    "access_report_stored": _not_implemented_yet("access milestone A3"),
}
