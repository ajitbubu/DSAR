"""Retention decisions and legal holds (M4).

Decisions are append-only: a change inserts a row that supersedes the current head.
The DB guarantees one linear chain per match (see migration 0005), and the service
serialises writers by locking the match row.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, aliased

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.policy.model import PolicyPack, RetentionDecisionCode
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.domain.retention.engine import MatchFacts, Outcome, evaluate
from idprivacy.platform.auth.rbac import StaffPrincipal
from idprivacy.platform.models import (
    DataMatch,
    LegalHold,
    PrivacyRequest,
    RequestIdentifier,
    RetentionDecision,
)

ACTOR = SystemActor("system:retention")
HOLD_SCOPES = ("CASE", "DATA_PRINCIPAL", "CONNECTOR", "RECORD_TYPE")
# Cases whose decisions a new legal hold must still reach (before any destructive work).
HOLD_REACHES = frozenset(
    {
        CaseStatus.RETENTION_EVALUATED,
        CaseStatus.UNDER_REVIEW,
        CaseStatus.PENDING_APPROVAL,
        CaseStatus.APPROVED,
        CaseStatus.REJECTED,
    }
)


class OverrideRejected(ValueError):
    pass


class StaleDecision(Exception):
    pass


def current_decisions(session: Session, request_id: UUID) -> dict[UUID, RetentionDecision]:
    """Map of data_match_id → current (unsuperseded) decision for a case."""
    newer = aliased(RetentionDecision)
    rows = session.execute(
        select(RetentionDecision).where(
            RetentionDecision.request_id == request_id,
            ~exists().where(newer.supersedes_id == RetentionDecision.id),
        )
    ).scalars()
    return {d.data_match_id: d for d in rows}


def history(session: Session, request_id: UUID) -> dict[UUID, list[RetentionDecision]]:
    out: dict[UUID, list[RetentionDecision]] = {}
    for d in session.execute(
        select(RetentionDecision)
        .where(RetentionDecision.request_id == request_id)
        .order_by(RetentionDecision.created_at)
    ).scalars():
        out.setdefault(d.data_match_id, []).append(d)
    return out


def active_hold_for(
    session: Session, *, request: PrivacyRequest, match: DataMatch
) -> LegalHold | None:
    candidates = {
        ("CASE", str(request.id)),
        ("DATA_PRINCIPAL", str(request.data_principal_id)),
        ("CONNECTOR", match.connector_id),
        ("RECORD_TYPE", match.record_type),
    }
    holds = session.execute(
        select(LegalHold).where(LegalHold.released_at.is_(None)).order_by(LegalHold.created_at)
    ).scalars()
    return next((h for h in holds if (h.scope, h.scope_ref) in candidates), None)


def _facts(session: Session, request: PrivacyRequest, match: DataMatch) -> MatchFacts:
    verified_types = set(
        session.execute(
            select(RequestIdentifier.type).where(
                RequestIdentifier.request_id == request.id,
                RequestIdentifier.assurance == "VERIFIED",
            )
        ).scalars()
    )
    assurance: Literal["VERIFIED", "CLAIMED"] = (
        "VERIFIED" if set(match.matched_on) <= verified_types else "CLAIMED"
    )
    hold = active_hold_for(session, request=request, match=match)
    return MatchFacts(
        match.record_type, frozenset(match.data_categories), assurance, hold.id if hold else None
    )


def _pack(session: Session, registry: PolicyRegistry, request: PrivacyRequest) -> PolicyPack:
    assert request.policy_pack_id is not None
    return registry.by_id(session, request.policy_pack_id).pack


def _insert(
    session: Session,
    request: PrivacyRequest,
    match: DataMatch,
    outcome: Outcome,
    supersedes: RetentionDecision | None,
) -> RetentionDecision:
    decision = RetentionDecision(
        tenant_id=request.tenant_id,
        request_id=request.id,
        data_match_id=match.id,
        decision=outcome.decision.value,
        source="ENGINE",
        rule_id=outcome.rule_id,
        exception_code=outcome.exception_code,
        legal_hold_id=outcome.legal_hold_id,
        supersedes_id=supersedes.id if supersedes else None,
    )
    session.add(decision)
    session.flush()
    return decision


def evaluate_case(
    session: Session, *, request: PrivacyRequest, registry: PolicyRegistry
) -> dict[str, int]:
    """Give every match an engine decision, then fire RETENTION_EVALUATED. Idempotent."""
    if request.status != CaseStatus.DISCOVERY_COMPLETE:
        return {}
    pack = _pack(session, registry, request)
    existing = current_decisions(session, request.id)
    counts: dict[str, int] = {}
    matches = (
        session.execute(
            select(DataMatch).where(DataMatch.request_id == request.id).order_by(DataMatch.id)
        )
        .scalars()
        .all()
    )
    for match in matches:
        decision = existing.get(match.id)
        if decision is None:
            decision = _insert(
                session, request, match, evaluate(pack, _facts(session, request, match)), None
            )
        counts[decision.decision] = counts.get(decision.decision, 0) + 1
    fire(session, request, "RETENTION_EVALUATED", actor=ACTOR, registry=registry)
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR.ref,
        action="retention.evaluated",
        object_type="privacy_request",
        object_id=request.id,
        details={"decisions": counts, "policy_pack": pack.ref},
    )
    return counts


@dataclass(frozen=True)
class OverrideInput:
    decision: RetentionDecisionCode
    exception_code: str
    exception_reason: str
    expected_current_id: UUID


def override(
    session: Session,
    *,
    request: PrivacyRequest,
    match_id: UUID,
    principal: StaffPrincipal,
    data: OverrideInput,
    registry: PolicyRegistry,
) -> RetentionDecision:
    if request.status != CaseStatus.UNDER_REVIEW:
        raise OverrideRejected("decisions can only be changed while the case is under review")
    # Serialise writers per case (the app role can't lock insert-only data_match rows).
    # uq_retention_decision_supersedes is the DB backstop against forked chains.
    session.execute(
        select(PrivacyRequest.id).where(PrivacyRequest.id == request.id).with_for_update()
    )
    match = session.execute(
        select(DataMatch).where(DataMatch.id == match_id, DataMatch.request_id == request.id)
    ).scalar_one_or_none()
    if match is None:
        raise LookupError(match_id)
    pack = _pack(session, registry, request)
    if data.exception_code not in {e.code for e in pack.exception_codes}:
        raise OverrideRejected(f"exception code must be one of {pack.ref}'s vocabulary")
    current = current_decisions(session, request.id).get(match.id)
    if current is None or current.id != data.expected_current_id:
        raise StaleDecision(str(match.id))
    hold = active_hold_for(session, request=request, match=match)
    if hold is not None and data.decision != RetentionDecisionCode.RETAIN:
        raise OverrideRejected("record is under an active legal hold and must be retained")
    decision = RetentionDecision(
        tenant_id=request.tenant_id,
        request_id=request.id,
        data_match_id=match.id,
        decision=data.decision.value,
        source="ANALYST_OVERRIDE",
        rule_id=None,
        exception_code=data.exception_code,
        exception_reason=data.exception_reason,
        legal_hold_id=hold.id if hold else None,
        decided_by=principal.user_id,
        supersedes_id=current.id,
    )
    session.add(decision)
    session.flush()
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="retention.overridden",
        object_type="data_match",
        object_id=match.id,
        details={
            "from": current.decision,
            "to": data.decision.value,
            "exception_code": data.exception_code,
            "request_id": str(request.id),
        },
    )
    return decision


def unresolved_manual_reviews(session: Session, request_id: UUID) -> int:
    return sum(
        d.decision == RetentionDecisionCode.MANUAL_REVIEW
        for d in current_decisions(session, request_id).values()
    )


# ---------- Legal holds ---------------------------------------------------------------


def place_hold(
    session: Session,
    *,
    tenant_id: UUID,
    scope: str,
    scope_ref: str,
    matter_ref: str,
    reason: str,
    principal: StaffPrincipal,
    registry: PolicyRegistry,
) -> tuple[LegalHold, int]:
    """Create a hold and apply it to open cases in scope. Returns (hold, decisions changed)."""
    hold = LegalHold(
        tenant_id=tenant_id,
        scope=scope,
        scope_ref=scope_ref,
        matter_ref=matter_ref,
        reason=reason,
        created_by=principal.user_id,
    )
    session.add(hold)
    session.flush()
    changed = 0
    open_cases = (
        session.execute(
            select(PrivacyRequest).where(PrivacyRequest.status.in_(HOLD_REACHES)).with_for_update()
        )
        .scalars()
        .all()
    )
    for request in open_cases:
        current = current_decisions(session, request.id)
        for match in session.execute(
            select(DataMatch).where(DataMatch.request_id == request.id)
        ).scalars():
            if active_hold_for(session, request=request, match=match) is None:
                continue
            head = current.get(match.id)
            if (
                head is not None
                and head.decision == RetentionDecisionCode.RETAIN
                and head.legal_hold_id is not None
            ):
                continue
            outcome = evaluate(_pack(session, registry, request), _facts(session, request, match))
            _insert(session, request, match, outcome, head)
            changed += 1
    audit.append(
        session,
        tenant_id=tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="legal_hold.placed",
        object_type="legal_hold",
        object_id=hold.id,
        details={"scope": scope, "matter_ref": matter_ref, "decisions_changed": changed},
    )
    return hold, changed


def release_hold(session: Session, *, hold_id: UUID, principal: StaffPrincipal) -> LegalHold:
    """Releasing never reverts decisions automatically; an analyst re-reviews them."""
    hold = session.execute(
        select(LegalHold).where(LegalHold.id == hold_id).with_for_update()
    ).scalar_one_or_none()
    if hold is None:
        raise LookupError(hold_id)
    if hold.released_at is not None:
        raise OverrideRejected("hold already released")
    hold.released_at, hold.released_by = datetime.now(UTC), principal.user_id
    audit.append(
        session,
        tenant_id=hold.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="legal_hold.released",
        object_type="legal_hold",
        object_id=hold.id,
        details={"scope": hold.scope, "matter_ref": hold.matter_ref},
    )
    return hold
