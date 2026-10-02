"""Disclosure review and the processing register (access milestone A2).

The disclosure view is the only place exported personal data leaves the API. It needs
``disclosure:read`` (analysts and approvers, not auditors), every read is audited, and
responses are never cached.
"""

import re
import unicodedata
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.disclosure import register as reg
from idprivacy.domain.disclosure import report as access_report
from idprivacy.domain.disclosure import service as disclosure
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import ConnectorConfig, DisclosureExport, PrivacyRequest

router = APIRouter(prefix="/v1", tags=["disclosure"])
Reviewer = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_REVIEW))]
ContentReader = Annotated[StaffPrincipal, Depends(Requires(Permission.DISCLOSURE_READ))]
CaseReader = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_READ))]
RegisterManager = Annotated[StaffPrincipal, Depends(Requires(Permission.REGISTER_MANAGE))]
Db = Annotated[Session, Depends(get_tenant_db)]
_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
CONNECTOR_RE = re.compile(r"^[a-z][a-z0-9_-]{1,39}$")


def _load(db: Session, case_id: UUID, *, lock: bool = False) -> PrivacyRequest:
    q = select(PrivacyRequest).where(PrivacyRequest.id == case_id)
    case = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if case is None:
        raise _NOT_FOUND
    return case


class ExportView(BaseModel):
    id: UUID
    round: int
    status: str
    error_code: str | None
    record_count: int
    field_count: int
    missing_count: int
    created_at: datetime
    finished_at: datetime | None


def _export_view(e: DisclosureExport) -> ExportView:
    return ExportView(
        id=e.id,
        round=e.round,
        status=e.status,
        error_code=e.error_code,
        record_count=e.record_count,
        field_count=e.field_count,
        missing_count=e.missing_count,
        created_at=e.created_at,
        finished_at=e.finished_at,
    )


@router.post(
    "/cases/{case_id}/disclosure/exports",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ExportView,
)
def request_export(case_id: UUID, principal: Reviewer, db: Db) -> ExportView:
    case = _load(db, case_id, lock=True)
    try:
        export = disclosure.request_export(db, request=case, principal=principal)
    except disclosure.DisclosureConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    db.flush()
    db.refresh(export)
    return _export_view(export)


class FieldView(BaseModel):
    name: str
    label: str
    category: str
    value: bool | int | str | None
    excluded: bool
    reason_code: str | None


class RecordView(BaseModel):
    match_id: UUID
    connector_id: str
    record_type: str
    excluded: bool
    reason_code: str | None
    fields: list[FieldView]


class Recipient(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=200)]
    kind: Literal["PROCESSOR", "FIDUCIARY", "OTHER"]


Purpose = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=200)]


class ProcessingView(BaseModel):
    connector_id: str
    display_name: str
    entry_id: UUID | None
    purposes: list[str]
    recipients: list[Recipient]


class ReasonCode(BaseModel):
    code: str
    label: str


class ReportInfo(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    download_count: int
    max_downloads: int
    purged_at: datetime | None
    record_count: int
    withheld_records: int
    withheld_fields: int


class DisclosureView(BaseModel):
    report: ReportInfo | None = None
    export: ExportView | None
    records: list[RecordView]
    missing: list[UUID]
    processing: list[ProcessingView]
    reason_codes: list[ReasonCode]
    disclosure_set_sha256: str | None


def _processing(db: Session, connector_ids: list[str]) -> list[ProcessingView]:
    register = reg.current_register(db)
    names = dict(
        db.execute(select(ConnectorConfig.connector_id, ConnectorConfig.display_name)).all()
    )
    out = []
    for cid in connector_ids:
        entry = register.get(cid)
        out.append(
            ProcessingView(
                connector_id=cid,
                display_name=names.get(cid, cid),
                entry_id=entry.id if entry else None,
                purposes=list(entry.purposes) if entry else [],
                recipients=[Recipient(**r) for r in entry.recipients] if entry else [],
            )
        )
    return out


@router.get("/cases/{case_id}/disclosure", response_model=DisclosureView)
def get_disclosure(
    case_id: UUID, principal: ContentReader, db: Db, request: Request, response: Response
) -> DisclosureView:
    response.headers["Cache-Control"] = "no-store"
    case = _load(db, case_id)
    if not disclosure.is_access_case(db, case.id):
        raise _NOT_FOUND
    svc = request.app.state.services
    # Before jurisdiction there's no pinned pack, so no reason vocabulary yet.
    pack = svc.registry.by_id(db, case.policy_pack_id).pack if case.policy_pack_id else None
    export = disclosure.latest_export(db, case.id)
    records: list[RecordView] = []
    missing: list[UUID] = []
    if export is not None and export.status == "READY" and export.purged_at is None:
        content = disclosure.load_content(export, cipher=svc.cipher, store=svc.blob_store)
        excluded = disclosure.current_exclusions(db, export.id)
        for r in content["records"]:
            mid = UUID(r["match_id"])
            whole = excluded.get((mid, None))
            records.append(
                RecordView(
                    match_id=mid,
                    connector_id=r["connector_id"],
                    record_type=r["record_type"],
                    excluded=whole is not None,
                    reason_code=whole.reason_code if whole else None,
                    fields=[
                        FieldView(
                            **f,
                            excluded=(mid, f["name"]) in excluded,
                            reason_code=(
                                excluded[(mid, f["name"])].reason_code
                                if (mid, f["name"]) in excluded
                                else None
                            ),
                        )
                        for f in r["fields"]
                    ],
                )
            )
        missing = [UUID(m) for m in content["missing"]]
        audit.append(
            db,
            tenant_id=case.tenant_id,
            actor_type="USER",
            actor_ref=str(principal.user_id),
            action="disclosure.viewed",
            object_type="privacy_request",
            object_id=case.id,
            details={"export_id": str(export.id), "records": len(records)},
        )
    r = access_report.latest_report(db, case.id)
    return DisclosureView(
        report=None
        if r is None
        else ReportInfo(
            id=r.id,
            created_at=r.created_at,
            expires_at=r.expires_at,
            download_count=r.download_count,
            max_downloads=r.max_downloads,
            purged_at=r.purged_at,
            record_count=r.record_count,
            withheld_records=r.withheld_records,
            withheld_fields=r.withheld_fields,
        ),
        export=_export_view(export) if export else None,
        records=records,
        missing=missing,
        processing=_processing(db, disclosure.case_connectors(db, case.id)),
        reason_codes=[ReasonCode(code=e.code, label=e.label) for e in pack.exception_codes]
        if pack
        else [],
        disclosure_set_sha256=disclosure.disclosure_set_hash(db, case.id),
    )


class ExclusionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    export_id: UUID
    data_match_id: UUID
    field_name: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.]{0,63}$")] | None = None
    action: Literal["EXCLUDE", "INCLUDE"]
    reason_code: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,39}$")] | None = None


class ExclusionResult(BaseModel):
    changed: bool
    disclosure_set_sha256: str | None


@router.post("/cases/{case_id}/disclosure/exclusions", response_model=ExclusionResult)
def set_exclusion(
    case_id: UUID, body: ExclusionBody, principal: Reviewer, db: Db, request: Request
) -> ExclusionResult:
    case = _load(db, case_id, lock=True)  # serialise writers per case
    svc = request.app.state.services
    export = disclosure.latest_export(db, case.id)
    if export is None or export.id != body.export_id or export.status != "READY":
        raise HTTPException(status.HTTP_409_CONFLICT, "this isn't the current export; reload")
    content = disclosure.load_content(export, cipher=svc.cipher, store=svc.blob_store)
    try:
        changed = disclosure.set_exclusion(
            db,
            request=case,
            principal=principal,
            data=disclosure.ExclusionInput(
                body.export_id, body.data_match_id, body.field_name, body.action, body.reason_code
            ),
            content=content,
            registry=svc.registry,
        )
    except disclosure.DisclosureConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    except disclosure.DisclosureInvalid as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    return ExclusionResult(
        changed=changed, disclosure_set_sha256=disclosure.disclosure_set_hash(db, case.id)
    )


# ---------- Processing register -------------------------------------------------------


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purposes: Annotated[list[Purpose], Field(min_length=1, max_length=10)]
    recipients: Annotated[list[Recipient], Field(max_length=20)]

    @field_validator("purposes")
    @classmethod
    def _printable(cls, v: list[str]) -> list[str]:
        for p in v:
            if any(unicodedata.category(c) in {"Cc", "Cf"} for c in p):
                raise ValueError("unsupported characters")
        return v


@router.get("/processing-register", response_model=list[ProcessingView])
def get_register(_p: CaseReader, db: Db) -> list[ProcessingView]:
    ids = sorted(db.execute(select(ConnectorConfig.connector_id)).scalars())
    return _processing(db, ids)


@router.post("/processing-register/{connector_id}", response_model=ProcessingView)
def update_register(
    connector_id: str, body: RegisterBody, principal: RegisterManager, db: Db
) -> Any:
    if not CONNECTOR_RE.fullmatch(connector_id):
        raise _NOT_FOUND
    try:
        reg.put_entry(
            db,
            tenant_id=principal.tenant_id,
            connector_id=connector_id,
            data=reg.RegisterInput(
                purposes=body.purposes, recipients=[r.model_dump() for r in body.recipients]
            ),
            principal=principal,
        )
    except reg.UnknownConnector:
        raise _NOT_FOUND from None
    return _processing(db, [connector_id])[0]
