"""Verification view, reconciliation, evidence package, uploads (M7; screens 10 and 11)."""

import hashlib
import uuid
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.evidence.uploads import MAX_UPLOAD_BYTES, UploadRejected, validate
from idprivacy.domain.verification import service as verification
from idprivacy.platform.auth.deps import Requires, get_tenant_db
from idprivacy.platform.auth.rbac import Permission, StaffPrincipal
from idprivacy.platform.models import (
    DataMatch,
    EvidenceArtifact,
    PrivacyRequest,
    VerificationResult,
)
from idprivacy.platform.storage import object_key

router = APIRouter(prefix="/v1/cases", tags=["verification", "evidence"])
Reader = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_READ))]
Reviewer = Annotated[StaffPrincipal, Depends(Requires(Permission.CASE_REVIEW))]
Db = Annotated[Session, Depends(get_tenant_db)]
_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


def _case(db: Session, case_id: UUID, *, lock: bool = False) -> PrivacyRequest:
    query = select(PrivacyRequest).where(PrivacyRequest.id == case_id)
    case = db.execute(query.with_for_update() if lock else query).scalar_one_or_none()
    if case is None:
        raise _NOT_FOUND
    return case


class ResultView(BaseModel):
    source_record_ref: str
    connector_id: str
    round: int
    expected: str
    observed_verify: str | None
    observed_rescan: str | None
    outcome: str
    note: str | None


class VerificationView(BaseModel):
    case_status: CaseStatus
    latest_round: int | None
    results: list[ResultView]


@router.get("/{case_id}/verification", response_model=VerificationView)
def get_verification(case_id: UUID, _p: Reader, db: Db) -> VerificationView:
    case = _case(db, case_id)
    rows = db.execute(
        select(VerificationResult, DataMatch)
        .join(DataMatch, DataMatch.id == VerificationResult.data_match_id)
        .where(VerificationResult.request_id == case.id)
        .order_by(
            VerificationResult.round.desc(), DataMatch.connector_id, DataMatch.source_record_ref
        )
    ).all()
    results = [
        ResultView(
            source_record_ref=m.source_record_ref,
            connector_id=m.connector_id,
            round=v.round,
            expected=v.expected,
            observed_verify=v.observed_verify,
            observed_rescan=v.observed_rescan,
            outcome=v.outcome,
            note=v.note,
        )
        for v, m in rows
    ]
    return VerificationView(
        case_status=CaseStatus(case.status),
        latest_round=results[0].round if results else None,
        results=results,
    )


@router.post("/{case_id}/reconcile", status_code=status.HTTP_202_ACCEPTED)
def reconcile(case_id: UUID, principal: Reviewer, db: Db, request: Request) -> dict[str, int]:
    case = _case(db, case_id, lock=True)
    try:
        created = verification.reconcile(
            db,
            request=case,
            principal_ref=str(principal.user_id),
            registry=request.app.state.services.registry,
        )
    except verification.ReconcileRejected as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return {"tasks": created}


class ArtifactView(BaseModel):
    id: UUID
    kind: str
    sha256: str
    manifest_sha256: str | None
    size_bytes: int
    media_type: str
    created_by: str
    created_at: datetime


def _artifact_view(a: EvidenceArtifact) -> ArtifactView:
    return ArtifactView(
        id=a.id,
        kind=a.kind,
        sha256=a.sha256,
        manifest_sha256=a.manifest_sha256,
        size_bytes=a.size_bytes,
        media_type=a.media_type,
        created_by=a.created_by,
        created_at=a.created_at,
    )


@router.get("/{case_id}/evidence", response_model=list[ArtifactView])
def list_evidence(case_id: UUID, _p: Reader, db: Db) -> list[ArtifactView]:
    case = _case(db, case_id)
    rows = db.execute(
        select(EvidenceArtifact)
        .where(EvidenceArtifact.request_id == case.id)
        .order_by(EvidenceArtifact.created_at.desc())
    ).scalars()
    return [_artifact_view(a) for a in rows]


@router.get("/{case_id}/evidence/{artifact_id}/content")
def download_evidence(
    case_id: UUID, artifact_id: UUID, principal: Reader, db: Db, request: Request
) -> StreamingResponse:
    case = _case(db, case_id)
    artifact = db.execute(
        select(EvidenceArtifact).where(
            EvidenceArtifact.id == artifact_id, EvidenceArtifact.request_id == case.id
        )
    ).scalar_one_or_none()
    if artifact is None:
        raise _NOT_FOUND
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="evidence.downloaded",
        object_type="evidence_artifact",
        object_id=artifact.id,
        details={"kind": artifact.kind, "sha256": artifact.sha256},
    )
    store = request.app.state.services.blob_store
    stream: Iterator[bytes] = store.stream(artifact.object_key)
    name = f"evidence-{case.display_id}-{artifact.kind.lower()}.{artifact.file_ext}"
    return StreamingResponse(
        stream,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Length": str(artifact.size_bytes),
            "X-Content-SHA256": artifact.sha256,
        },
    )


@router.post(
    "/{case_id}/evidence", status_code=status.HTTP_201_CREATED, response_model=ArtifactView
)
async def upload_evidence(
    case_id: UUID,
    principal: Reviewer,
    db: Db,
    request: Request,
    file: Annotated[UploadFile, File()],
) -> ArtifactView:
    case = _case(db, case_id)
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        valid = validate(file.filename or "", file.content_type or "", data)
    except UploadRejected as exc:
        raise HTTPException(exc.status, str(exc)) from None
    artifact_id = uuid.uuid4()
    # The original filename is discarded: the key is server-generated and opaque.
    key = object_key(case.tenant_id, case.id, artifact_id, valid.ext)
    request.app.state.services.blob_store.put(key, data, valid.media_type)
    artifact = EvidenceArtifact(
        id=artifact_id,
        tenant_id=case.tenant_id,
        request_id=case.id,
        kind="UPLOAD",
        object_key=key,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=valid.media_type,
        file_ext=valid.ext,
        created_by=str(principal.user_id),
    )
    db.add(artifact)
    db.flush()
    audit.append(
        db,
        tenant_id=case.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="evidence.uploaded",
        object_type="evidence_artifact",
        object_id=artifact.id,
        details={"media_type": valid.media_type, "size": len(data), "sha256": artifact.sha256},
    )
    return _artifact_view(artifact)
