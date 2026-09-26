from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal

router = APIRouter(prefix="/v1", tags=["audit"])


class ChainVerificationResponse(BaseModel):
    ok: bool
    events_checked: int
    first_broken_seq: int | None


@router.post("/audit/verify", response_model=ChainVerificationResponse)
def verify_audit_chain(
    principal: Annotated[StaffPrincipal, Depends(Requires(Permission.AUDIT_VERIFY))],
    db: Annotated[Session, Depends(get_tenant_db)],
) -> ChainVerificationResponse:
    result = audit.verify_chain(db, principal.tenant_id)
    audit.append(
        db,
        tenant_id=principal.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="audit.chain_verified",
        object_type="tenant",
        object_id=principal.tenant_id,
        details={"ok": result.ok, "events_checked": result.events_checked},
    )
    return ChainVerificationResponse(**result.__dict__)
