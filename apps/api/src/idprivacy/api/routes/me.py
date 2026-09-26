from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from idprivacy.platform.auth.deps import Requires
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal

router = APIRouter(prefix="/v1", tags=["identity"])


class MeResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    roles: list[str]
    permissions: list[str]


@router.get("/me", response_model=MeResponse)
def me(principal: Annotated[StaffPrincipal, Depends(Requires(Permission.SELF_READ))]) -> MeResponse:
    return MeResponse(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
    )
