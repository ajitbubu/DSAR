"""Legal holds (M4): placing a hold forces RETAIN on records in scope, including open cases."""

import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.retention import service as retention
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import ConnectorConfig, LegalHold, PrivacyRequest

router = APIRouter(prefix="/v1/legal-holds", tags=["legal-holds"])
Reader = Annotated[StaffPrincipal, Depends(Requires(Permission.LEGAL_HOLD_READ))]
Manager = Annotated[StaffPrincipal, Depends(Requires(Permission.LEGAL_HOLD_MANAGE))]
Db = Annotated[Session, Depends(get_tenant_db)]
Text10 = Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=2000)]


class HoldBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["CASE", "DATA_PRINCIPAL", "CONNECTOR", "RECORD_TYPE"]
    case_id: UUID | None = None  # for CASE / DATA_PRINCIPAL (server derives the ref)
    scope_ref: Annotated[str, StringConstraints(max_length=64)] | None = None
    matter_ref: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ./_-]{1,63}$")]
    reason: Text10

    @model_validator(mode="after")
    def _shape(self) -> "HoldBody":
        needs_case = self.scope in ("CASE", "DATA_PRINCIPAL")
        if needs_case != (self.case_id is not None) or needs_case == (self.scope_ref is not None):
            raise ValueError("CASE/DATA_PRINCIPAL holds take case_id; others take scope_ref")
        return self


class HoldView(BaseModel):
    id: UUID
    scope: str
    scope_ref: str
    matter_ref: str
    reason: str
    created_by: UUID
    created_at: datetime
    released_at: datetime | None
    decisions_changed: int | None = None


def _view(h: LegalHold, changed: int | None = None) -> HoldView:
    return HoldView(
        id=h.id,
        scope=h.scope,
        scope_ref=h.scope_ref,
        matter_ref=h.matter_ref,
        reason=h.reason,
        created_by=h.created_by,
        created_at=h.created_at,
        released_at=h.released_at,
        decisions_changed=changed,
    )


@router.get("", response_model=list[HoldView])
def list_holds(_p: Reader, db: Db) -> list[HoldView]:
    rows = db.execute(select(LegalHold).order_by(LegalHold.created_at.desc()).limit(200))
    return [_view(h) for h in rows.scalars()]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=HoldView)
def place_hold(body: HoldBody, principal: Manager, db: Db, request: Request) -> HoldView:
    if body.scope in ("CASE", "DATA_PRINCIPAL"):
        case = db.get(PrivacyRequest, body.case_id)
        if case is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
        ref = str(case.id if body.scope == "CASE" else case.data_principal_id)
    elif body.scope == "CONNECTOR":
        assert body.scope_ref is not None
        if (
            db.execute(
                select(ConnectorConfig.id).where(ConnectorConfig.connector_id == body.scope_ref)
            ).first()
            is None
        ):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
        ref = body.scope_ref
    else:
        assert body.scope_ref is not None
        if not re.fullmatch(r"[a-z][a-z0-9_.]{1,63}", body.scope_ref):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid record type")
        ref = body.scope_ref
    hold, changed = retention.place_hold(
        db,
        tenant_id=principal.tenant_id,
        scope=body.scope,
        scope_ref=ref,
        matter_ref=body.matter_ref,
        reason=body.reason,
        principal=principal,
        registry=request.app.state.services.registry,
    )
    return _view(hold, changed)


@router.post("/{hold_id}/release", response_model=HoldView)
def release_hold(hold_id: UUID, principal: Manager, db: Db) -> HoldView:
    try:
        return _view(retention.release_hold(db, hold_id=hold_id, principal=principal))
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found") from None
    except retention.OverrideRejected as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
