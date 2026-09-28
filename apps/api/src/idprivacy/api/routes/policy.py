"""Rights and policy-pack catalogue (read-only for staff)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal

router = APIRouter(prefix="/v1", tags=["policy"])


class RightSummary(BaseModel):
    code: str
    title: str
    reference: str | None
    executable: bool
    workflow: str
    sla_validated: bool


class PackSummary(BaseModel):
    code: str
    version: str
    title: str
    sha256: str
    legal_review: str
    rights: list[RightSummary]


@router.get("/policy-packs", response_model=list[PackSummary])
def list_policy_packs(
    request: Request,
    _principal: Annotated[StaffPrincipal, Depends(Requires(Permission.POLICY_READ))],
    db: Annotated[Session, Depends(get_tenant_db)],
) -> list[PackSummary]:
    result = []
    for published in request.app.state.services.registry.all_published(db):
        pack = published.pack
        result.append(
            PackSummary(
                code=pack.code,
                version=pack.version,
                title=pack.title,
                sha256=published.sha256,
                legal_review=pack.legal_review,
                rights=[
                    RightSummary(
                        code=code,
                        title=r.title,
                        reference=r.reference,
                        executable=r.executable,
                        workflow=r.workflow,
                        sla_validated=pack.sla[code].validated,
                    )
                    for code, r in pack.rights.items()
                ],
            )
        )
    return result
