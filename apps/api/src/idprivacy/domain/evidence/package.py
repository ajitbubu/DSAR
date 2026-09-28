"""Evidence package (M7; ADR-0007).

A deterministic ZIP: fixed file order and entry timestamps, canonical JSON. For the same
case data and generation time it produces identical bytes, so every hash can be
recomputed and compared. Identifiers
appear only masked. Audit details are already redacted when written.
"""

import hashlib
import io
import json
import uuid
import zipfile
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.identity.masking import mask
from idprivacy.domain.identity.resolution import CTX_REQUEST_IDENTIFIER
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    Approval,
    ApprovalSubmission,
    AuditEvent,
    ConnectorConfig,
    ConnectorExecution,
    DataMatch,
    EvidenceArtifact,
    FulfilmentTask,
    IdentityVerification,
    JurisdictionDecision,
    PrivacyRequest,
    RequestIdentifier,
    RequestRight,
    RetentionDecision,
    VerificationResult,
)
from idprivacy.platform.storage import BlobStore, object_key

ACTOR = SystemActor("system:evidence")
FORMAT_VERSION = "1"
_ZIP_TIME = (2000, 1, 1, 0, 0, 0)


def _j(obj: Any) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False, default=str) + "\n"
    ).encode()


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def collect(session: Session, request: PrivacyRequest, cipher: FieldCipher) -> dict[str, Any]:
    rid = request.id
    matches = {
        m.id: m
        for m in session.execute(select(DataMatch).where(DataMatch.request_id == rid)).scalars()
    }
    connectors = {c.id: c.connector_id for c in session.execute(select(ConnectorConfig)).scalars()}
    tasks = (
        session.execute(
            select(FulfilmentTask)
            .where(FulfilmentTask.request_id == rid)
            .order_by(FulfilmentTask.data_match_id, FulfilmentTask.round)
        )
        .scalars()
        .all()
    )
    executions = (
        session.execute(
            select(ConnectorExecution)
            .where(ConnectorExecution.fulfilment_task_id.in_([t.id for t in tasks]))
            .order_by(
                ConnectorExecution.fulfilment_task_id,
                ConnectorExecution.operation,
                ConnectorExecution.attempt_no,
            )
        )
        .scalars()
        .all()
    )
    decision = session.execute(
        select(JurisdictionDecision).where(JurisdictionDecision.request_id == rid)
    ).scalar_one_or_none()
    challenge_ids = list(
        session.execute(
            select(IdentityVerification.id).where(IdentityVerification.request_id == rid)
        ).scalars()
    )
    related = [rid, *matches, *[t.id for t in tasks], *challenge_ids]
    events = (
        session.execute(
            select(AuditEvent).where(AuditEvent.object_id.in_(related)).order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )
    identifiers = [
        {
            "type": r.type,
            "assurance": r.assurance,
            "masked": mask(
                r.type, cipher.decrypt(r.tenant_id, CTX_REQUEST_IDENTIFIER, r.enc_value)
            ),
        }
        for r in session.execute(
            select(RequestIdentifier)
            .where(RequestIdentifier.request_id == rid)
            .order_by(RequestIdentifier.type)
        ).scalars()
    ]

    def ref(match_id: UUID) -> str:
        return matches[match_id].source_record_ref

    return {
        "case": {
            "request_id": str(rid),
            "display_id": request.display_id,
            "tenant_id": str(request.tenant_id),
            "status": request.status,
            "rights": sorted(
                r.right_code
                for r in session.execute(
                    select(RequestRight).where(RequestRight.request_id == rid)
                ).scalars()
            ),
            "submitted_at": _iso(request.submitted_at),
            "identifiers": identifiers,
        },
        "jurisdiction": None
        if decision is None
        else {
            "outcome": decision.outcome,
            "policy_pack": f"{decision.regulation}@{decision.policy_pack_version}"
            if decision.regulation
            else None,
            "rationale": decision.rationale,
            "inputs": decision.inputs,
        },
        "discovery": [
            {
                "match_id": str(m.id),
                "connector": m.connector_id,
                "record": m.source_record_ref,
                "record_type": m.record_type,
                "data_categories": m.data_categories,
                "matched_on": m.matched_on,
                "content_fingerprint": m.content_fingerprint,
            }
            for m in sorted(matches.values(), key=lambda m: m.source_record_ref)
        ],
        "decisions": [
            {
                "record": ref(d.data_match_id),
                "decision_id": str(d.id),
                "decision": d.decision,
                "source": d.source,
                "rule_id": d.rule_id,
                "exception_code": d.exception_code,
                "exception_reason": d.exception_reason,
                "legal_hold_id": str(d.legal_hold_id) if d.legal_hold_id else None,
                "decided_by": str(d.decided_by) if d.decided_by else None,
                "supersedes_id": str(d.supersedes_id) if d.supersedes_id else None,
                "at": _iso(d.created_at),
            }
            for d in session.execute(
                select(RetentionDecision)
                .where(RetentionDecision.request_id == rid)
                .order_by(RetentionDecision.created_at, RetentionDecision.id)
            ).scalars()
        ],
        "approvals": {
            "submissions": [
                {
                    "id": str(s.id),
                    "submitted_by": str(s.submitted_by),
                    "case_version": s.case_version,
                    "decision_set_sha256": s.decision_set_sha256,
                    "at": _iso(s.created_at),
                }
                for s in session.execute(
                    select(ApprovalSubmission)
                    .where(ApprovalSubmission.request_id == rid)
                    .order_by(ApprovalSubmission.created_at)
                ).scalars()
            ],
            "decisions": [
                {
                    "id": str(a.id),
                    "outcome": a.outcome,
                    "submitted_by": str(a.submitted_by),
                    "approved_by": str(a.approved_by),
                    "case_version": a.case_version,
                    "decision_set_sha256": a.decision_set_sha256,
                    "comment": a.comment,
                    "at": _iso(a.created_at),
                }
                for a in session.execute(
                    select(Approval).where(Approval.request_id == rid).order_by(Approval.created_at)
                ).scalars()
            ],
        },
        "fulfilment": [
            {
                "task_id": str(t.id),
                "record": ref(t.data_match_id),
                "connector": connectors.get(t.connector_config_id),
                "round": t.round,
                "action": t.action,
                "status": t.status,
                "idempotency_key": t.idempotency_key,
                "receipt_id": t.receipt_id,
                "outcome": t.outcome,
                "skip_reason": t.skip_reason,
                "attempts": t.attempt_count,
            }
            for t in tasks
        ],
        "connector_executions": [
            {
                "task_id": str(e.fulfilment_task_id),
                "operation": e.operation,
                "attempt": e.attempt_no,
                "outcome": e.outcome,
                "error_code": e.error_code,
                "receipt_id": e.receipt_id,
                "replayed": e.replayed,
                "evidence": e.evidence,
                "evidence_sha256": e.evidence_sha256,
                "at": _iso(e.finished_at),
            }
            for e in executions
        ],
        "verification": [
            {
                "record": ref(v.data_match_id),
                "round": v.round,
                "expected": v.expected,
                "observed_verify": v.observed_verify,
                "observed_rescan": v.observed_rescan,
                "outcome": v.outcome,
            }
            for v in session.execute(
                select(VerificationResult)
                .where(VerificationResult.request_id == rid)
                .order_by(VerificationResult.round, VerificationResult.data_match_id)
            ).scalars()
        ],
        "audit_timeline": [
            {
                "seq": e.seq,
                "at": _iso(e.occurred_at),
                "actor_type": e.actor_type,
                "actor_ref": e.actor_ref,
                "action": e.action,
                "object_type": e.object_type,
                "object_id": str(e.object_id),
                "details": e.details,
                "hash": e.hash,
            }
            for e in events
        ],
    }


FILES = [
    ("case.json", "case"),
    ("jurisdiction.json", "jurisdiction"),
    ("discovery.json", "discovery"),
    ("decisions.json", "decisions"),
    ("approvals.json", "approvals"),
    ("fulfilment.json", "fulfilment"),
    ("connector_evidence.json", "connector_executions"),
    ("verification_report.json", "verification"),
    ("audit_timeline.json", "audit_timeline"),
]


def build(data: dict[str, Any], generated_at: datetime) -> tuple[bytes, str, dict[str, Any]]:
    """Returns (zip bytes, manifest sha256, manifest)."""
    contents = {name: _j(data[key]) for name, key in FILES}
    manifest = {
        "format_version": FORMAT_VERSION,
        "request_id": data["case"]["request_id"],
        "display_id": data["case"]["display_id"],
        "policy_pack": (data["jurisdiction"] or {}).get("policy_pack"),
        "generated_at": _iso(generated_at),
        "files": [
            {"name": n, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
            for n, b in contents.items()
        ],
    }
    manifest_bytes = _j(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in [
            *contents.items(),
            ("manifest.json", manifest_bytes),
            ("manifest.sha256", f"{manifest_sha}  manifest.json\n".encode()),
        ]:
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
    return buf.getvalue(), manifest_sha, manifest


def generate(
    engine: Engine,
    *,
    tenant_id: UUID,
    request_id: UUID,
    store: BlobStore,
    registry: PolicyRegistry,
    cipher: FieldCipher,
) -> UUID | None:
    """Build, upload and register the package, then fire EVIDENCE_READY. Idempotent."""
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        request = s.get(PrivacyRequest, request_id)
        if request is None or request.status != CaseStatus.VERIFIED_COMPLETE:
            return None
        data = collect(s, request, cipher)
    blob, manifest_sha, _ = build(data, datetime.now(UTC))
    artifact_id = uuid.uuid4()
    key = object_key(tenant_id, request_id, artifact_id, "zip")
    store.put(key, blob, "application/zip")  # an orphan on a later failure is harmless
    with tenant_session(engine, ctx) as s:
        request = s.execute(
            select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
        ).scalar_one()
        if request.status != CaseStatus.VERIFIED_COMPLETE:
            return None
        package_sha = hashlib.sha256(blob).hexdigest()
        s.add(
            EvidenceArtifact(
                id=artifact_id,
                tenant_id=tenant_id,
                request_id=request_id,
                kind="PACKAGE",
                object_key=key,
                sha256=package_sha,
                manifest_sha256=manifest_sha,
                size_bytes=len(blob),
                media_type="application/zip",
                file_ext="zip",
                created_by=ACTOR.ref,
            )
        )
        s.flush()
        # The manifest hash enters the tamper-evident audit chain.
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="SYSTEM",
            actor_ref=ACTOR.ref,
            action="evidence.package_generated",
            object_type="evidence_artifact",
            object_id=artifact_id,
            details={
                "manifest_sha256": manifest_sha,
                "package_sha256": package_sha,
                "request_id": str(request_id),
                "size": len(blob),
            },
        )
        fire(s, request, "EVIDENCE_READY", actor=ACTOR, registry=registry)
    return artifact_id
