"""Generic executor for policy-pack workflows (ADR-0005).

Handlers call ``fire(...)`` with an event name. Which transitions exist, who may fire
them and which guards apply all come from the case's pinned pack, not from code.
"""

from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from idprivacy.domain.cases.lifecycle import CaseStatus, InvalidTransition, apply_status
from idprivacy.domain.policy.guards import GUARDS
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.auth.rbac import StaffPrincipal
from idprivacy.platform.models import PrivacyRequest


@dataclass(frozen=True)
class SystemActor:
    ref: str


Actor = SystemActor | StaffPrincipal


class TransitionForbidden(Exception):
    pass


class GuardFailed(Exception):
    def __init__(self, guard: str, reason: str) -> None:
        super().__init__(f"{guard}: {reason}")
        self.guard = guard
        self.reason = reason


def fire(
    session: Session, request: PrivacyRequest, event: str, *, actor: Actor, registry: PolicyRegistry
) -> CaseStatus:
    if request.policy_pack_id is None or request.workflow_code is None:
        raise InvalidTransition("case is not bound to a policy-pack workflow")
    pack = registry.by_id(session, request.policy_pack_id).pack
    workflow = pack.workflows[request.workflow_code]
    current = CaseStatus(request.status)
    transition = workflow.find(event, current)
    if transition is None:
        raise InvalidTransition(f"{event} not allowed from {current} in {pack.ref}")

    actor_type: Literal["SYSTEM", "USER"]
    if transition.actor == "SYSTEM":
        if not isinstance(actor, SystemActor):
            raise TransitionForbidden(f"{event} can only be fired by the system")
        actor_type, actor_ref = "SYSTEM", actor.ref
    else:
        if not isinstance(actor, StaffPrincipal) or actor.tenant_id != request.tenant_id:
            raise TransitionForbidden(f"{event} requires a staff user of this tenant")
        assert transition.permission is not None  # enforced by the pack model
        if not actor.has(transition.permission):
            raise TransitionForbidden(f"{event} requires {transition.permission}")
        actor_type, actor_ref = "USER", str(actor.user_id)

    for name in transition.guards:
        result = GUARDS[name](session, request)
        if not result.ok:
            raise GuardFailed(name, result.reason)

    apply_status(
        session,
        request,
        event=event,
        target=transition.to,
        actor_type=actor_type,
        actor_ref=actor_ref,
        details={"policy_pack": pack.ref, "workflow": request.workflow_code},
    )
    return transition.to
