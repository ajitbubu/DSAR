"""Disclosure review for access requests (docs/milestones-access.md, A2).

1. ``request_export``: an analyst asks for a fresh export round (case UNDER_REVIEW).
2. ``run_export``: the worker calls each connector's ``export_records`` outside any DB
   transaction, encrypts the whole bundle with the tenant key and stores it privately.
   The database and the audit trail get only a hash and counts, never content.
3. ``set_exclusion``: the analyst withholds a record or one field, with a reason from
   the pinned pack's exception vocabulary. Append-only; the latest row per key wins.
4. ``disclosure_set_hash``: binds export content, exclusions and the processing register
   versions. Maker-checker approval is bound to it (approvals.decision_set_hash).
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from idprivacy_connector_sdk import Connector, ConnectorError, ExportRequest
from idprivacy_connector_sdk.models import MAX_EXPORT_RECORDS
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.disclosure.register import current_register
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform import outbox
from idprivacy.platform.auth.rbac import StaffPrincipal
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    ConnectorConfig,
    DataMatch,
    DisclosureExclusion,
    DisclosureExport,
    DiscoveryJob,
    PrivacyRequest,
    RequestRight,
)
from idprivacy.platform.storage import BlobStore, object_key

ACCESS_RIGHT = "ACCESS"
ConnectorFactory = Callable[[ConnectorConfig], Connector]


class DisclosureConflict(Exception):
    """409: the case isn't in a state where this is allowed, or the export moved on."""


class DisclosureInvalid(Exception):
    """422: the record, field or reason isn't valid for this export."""


class ContentIntegrityError(Exception):
    """The stored export doesn't match its recorded hash."""


def _context(export_id: UUID) -> str:
    return f"disclosure_export:{export_id}"


def is_access_case(session: Session, request_id: UUID) -> bool:
    return (
        session.execute(
            select(RequestRight.id).where(
                RequestRight.request_id == request_id, RequestRight.right_code == ACCESS_RIGHT
            )
        ).first()
        is not None
    )


def latest_export(session: Session, request_id: UUID) -> DisclosureExport | None:
    return session.execute(
        select(DisclosureExport)
        .where(DisclosureExport.request_id == request_id)
        .order_by(DisclosureExport.round.desc())
        .limit(1)
    ).scalar_one_or_none()


def case_matches(session: Session, request_id: UUID) -> list[DataMatch]:
    """Records found by the case's initial discovery, in a stable order."""
    return list(
        session.execute(
            select(DataMatch)
            .join(DiscoveryJob, DiscoveryJob.id == DataMatch.discovery_job_id)
            .where(DataMatch.request_id == request_id, DiscoveryJob.purpose == "INITIAL")
            .order_by(DataMatch.connector_id, DataMatch.source_record_ref)
        ).scalars()
    )


def request_export(
    session: Session, *, request: PrivacyRequest, principal: StaffPrincipal
) -> DisclosureExport:
    if request.status != CaseStatus.UNDER_REVIEW:
        raise DisclosureConflict("records can only be exported while the case is under review")
    if not is_access_case(session, request.id):
        raise DisclosureConflict("only access requests have a disclosure")
    latest = latest_export(session, request.id)
    if latest is not None and latest.status in ("PENDING", "RUNNING"):
        return latest  # one in flight already; don't queue a duplicate
    export = DisclosureExport(
        tenant_id=request.tenant_id,
        request_id=request.id,
        round=(latest.round + 1) if latest else 1,
        status="PENDING",
        requested_by=principal.user_id,
    )
    session.add(export)
    session.flush()
    outbox.enqueue(
        session,
        tenant_id=request.tenant_id,
        topic="case.export_requested",
        payload={"request_id": request.id, "export_id": export.id},
    )
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="disclosure.export_requested",
        object_type="privacy_request",
        object_id=request.id,
        details={"export_id": str(export.id), "round": export.round},
    )
    return export


@dataclass(frozen=True)
class ExportOutcome:
    status: str
    error_code: str | None = None
    retryable: bool = False


def canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def run_export(
    engine: Engine,
    *,
    tenant_id: UUID,
    export_id: UUID,
    factory: ConnectorFactory,
    cipher: FieldCipher,
    store: BlobStore,
) -> ExportOutcome:
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        export = s.execute(
            select(DisclosureExport)
            .where(DisclosureExport.id == export_id)
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if export is None:
            return ExportOutcome("SKIPPED")
        if export.status == "READY":
            return ExportOutcome("READY")
        latest = latest_export(s, export.request_id)
        if latest is None or latest.id != export.id:
            return ExportOutcome("SUPERSEDED")
        request_id = export.request_id
        export.status, export.attempts, export.error_code = "RUNNING", export.attempts + 1, None
        plan: dict[UUID, list[tuple[UUID, str, str]]] = {}
        connector_ids: dict[UUID, str] = {}
        for m in case_matches(s, request_id):
            job = s.get(DiscoveryJob, m.discovery_job_id)
            assert job is not None
            plan.setdefault(job.connector_config_id, []).append(
                (m.id, m.source_record_ref, m.connector_id)
            )
            connector_ids[job.connector_config_id] = m.connector_id
        connectors = {
            cid: factory(cfg) for cid in plan if (cfg := s.get(ConnectorConfig, cid)) is not None
        }

    records: list[dict[str, Any]] = []
    missing: list[str] = []
    try:
        for config_id, items in plan.items():
            by_ref = {ref: match_id for match_id, ref, _ in items}
            refs = sorted(by_ref)
            exported: dict[str, Any] = {}
            for i in range(0, len(refs), MAX_EXPORT_RECORDS):
                chunk = refs[i : i + MAX_EXPORT_RECORDS]
                bundle = connectors[config_id].export_records(
                    ExportRequest(source_record_refs=chunk)
                )
                exported.update({r.source_record_ref: r for r in bundle.records})
            for ref in refs:
                rec = exported.get(ref)
                if rec is None:
                    missing.append(str(by_ref[ref]))
                    continue
                records.append(
                    {
                        "match_id": str(by_ref[ref]),
                        "connector_id": connector_ids[config_id],
                        "record_type": rec.record_type,
                        "fields": [f.model_dump(mode="json") for f in rec.fields],
                    }
                )
    except ConnectorError as exc:
        with tenant_session(engine, ctx) as s:
            export = s.get(DisclosureExport, export_id)
            assert export is not None
            export.status, export.error_code = "FAILED", exc.code
            export.finished_at = datetime.now(UTC)
            audit.append(
                s,
                tenant_id=tenant_id,
                actor_type="SYSTEM",
                actor_ref="system:disclosure",
                action="disclosure.export_failed",
                object_type="privacy_request",
                object_id=request_id,
                details={
                    "export_id": str(export_id),
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                    "attempt": export.attempts,
                },
            )
        return ExportOutcome("FAILED", exc.code, exc.retryable)

    doc = {"export_id": str(export_id), "records": records, "missing": sorted(missing)}
    body = canonical(doc)
    sha = hashlib.sha256(body).hexdigest()
    key = object_key(tenant_id, request_id, export_id, "enc")
    store.put(
        key,
        cipher.encrypt(tenant_id, _context(export_id), body.decode()).encode(),
        "application/octet-stream",
    )
    with tenant_session(engine, ctx) as s:
        export = s.get(DisclosureExport, export_id)
        assert export is not None
        export.status, export.object_key, export.content_sha256 = "READY", key, sha
        export.record_count = len(records)
        export.field_count = sum(len(r["fields"]) for r in records)
        export.missing_count = len(missing)
        export.finished_at = datetime.now(UTC)
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="SYSTEM",
            actor_ref="system:disclosure",
            action="disclosure.export_ready",
            object_type="privacy_request",
            object_id=request_id,
            details={
                "export_id": str(export_id),
                "round": export.round,
                "records": export.record_count,
                "fields": export.field_count,
                "missing": export.missing_count,
                "content_sha256": sha,
            },
        )
    return ExportOutcome("READY")


def load_content(
    export: DisclosureExport, *, cipher: FieldCipher, store: BlobStore
) -> dict[str, Any]:
    """Decrypt a READY export. Callers must be authorised and must audit the read."""
    assert export.status == "READY" and export.object_key and export.content_sha256
    token = b"".join(store.stream(export.object_key)).decode()
    body = cipher.decrypt(export.tenant_id, _context(export.id), token).encode()
    if hashlib.sha256(body).hexdigest() != export.content_sha256:
        raise ContentIntegrityError(str(export.id))
    content: dict[str, Any] = json.loads(body)
    return content


ExclusionKey = tuple[UUID, str | None]


def current_exclusions(
    session: Session, export_id: UUID
) -> dict[ExclusionKey, DisclosureExclusion]:
    """Effective exclusions: latest row per (record, field), where that row is EXCLUDE."""
    latest: dict[ExclusionKey, DisclosureExclusion] = {}
    for row in session.execute(
        select(DisclosureExclusion)
        .where(DisclosureExclusion.export_id == export_id)
        .order_by(DisclosureExclusion.created_at, DisclosureExclusion.id)
    ).scalars():
        latest[(row.data_match_id, row.field_name)] = row
    return {k: v for k, v in latest.items() if v.action == "EXCLUDE"}


def exclusion_authors(session: Session, request_id: UUID) -> set[UUID]:
    export = latest_export(session, request_id)
    if export is None:
        return set()
    return set(
        session.execute(
            select(DisclosureExclusion.created_by).where(DisclosureExclusion.export_id == export.id)
        ).scalars()
    )


@dataclass(frozen=True)
class ExclusionInput:
    export_id: UUID
    data_match_id: UUID
    field_name: str | None
    action: str  # EXCLUDE | INCLUDE
    reason_code: str | None


def set_exclusion(
    session: Session,
    *,
    request: PrivacyRequest,
    principal: StaffPrincipal,
    data: ExclusionInput,
    content: dict[str, Any],
    registry: PolicyRegistry,
) -> bool:
    """Record an exclusion change. Returns False if it was already in that state."""
    if request.status != CaseStatus.UNDER_REVIEW:
        raise DisclosureConflict("the disclosure can only change while the case is under review")
    export = latest_export(session, request.id)
    if export is None or export.id != data.export_id or export.status != "READY":
        raise DisclosureConflict("this isn't the current export; reload")
    record = next((r for r in content["records"] if r["match_id"] == str(data.data_match_id)), None)
    if record is None:
        raise DisclosureInvalid("record isn't in this export")
    if data.field_name is not None and data.field_name not in {f["name"] for f in record["fields"]}:
        raise DisclosureInvalid("field isn't in this record")
    if data.action == "EXCLUDE":
        assert request.policy_pack_id is not None
        pack = registry.by_id(session, request.policy_pack_id).pack
        if data.reason_code not in {e.code for e in pack.exception_codes}:
            raise DisclosureInvalid(f"reason must be one of {pack.ref}'s exception codes")
    elif data.reason_code is not None:
        raise DisclosureInvalid("including a record or field takes no reason")

    key = (data.data_match_id, data.field_name)
    current = current_exclusions(session, export.id).get(key)
    if (data.action == "INCLUDE" and current is None) or (
        data.action == "EXCLUDE" and current is not None and current.reason_code == data.reason_code
    ):
        return False
    session.add(
        DisclosureExclusion(
            tenant_id=request.tenant_id,
            request_id=request.id,
            export_id=export.id,
            data_match_id=data.data_match_id,
            field_name=data.field_name,
            action=data.action,
            reason_code=data.reason_code,
            created_by=principal.user_id,
        )
    )
    session.flush()
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="USER",
        actor_ref=str(principal.user_id),
        action="disclosure.exclusion_changed",
        object_type="privacy_request",
        object_id=request.id,
        details={
            "export_id": str(export.id),
            "data_match_id": str(data.data_match_id),
            "field_name": data.field_name,
            "action": data.action,
            "reason_code": data.reason_code,
        },
    )
    return True


def case_connectors(session: Session, request_id: UUID) -> list[str]:
    return sorted(
        session.execute(
            select(func.distinct(DataMatch.connector_id))
            .join(DiscoveryJob, DiscoveryJob.id == DataMatch.discovery_job_id)
            .where(DataMatch.request_id == request_id, DiscoveryJob.purpose == "INITIAL")
        ).scalars()
    )


def disclosure_set_hash(session: Session, request_id: UUID) -> str | None:
    """None for cases without a disclosure (e.g. erasure), so their hashes don't change."""
    export = latest_export(session, request_id)
    if export is None:
        return None
    register = current_register(session)
    body = {
        "export_id": str(export.id),
        "status": export.status,
        "content_sha256": export.content_sha256,
        "exclusions": sorted(
            (str(m), f or "", row.reason_code or "")
            for (m, f), row in current_exclusions(session, export.id).items()
        ),
        "register": sorted(
            (c, str(register[c].id) if c in register else "")
            for c in case_connectors(session, request_id)
        ),
    }
    return hashlib.sha256(canonical(body)).hexdigest()


def review_problem(session: Session, request: PrivacyRequest) -> str | None:
    """Why the disclosure isn't ready to submit, or None. Backs the pack guard."""
    export = latest_export(session, request.id)
    if export is None:
        return "export the records before submitting"
    if export.status != "READY":
        return f"the latest export is {export.status.lower()}"
    register = current_register(session)
    uncovered = [c for c in case_connectors(session, request.id) if c not in register]
    if uncovered:
        return "the processing register has no entry for " + ", ".join(uncovered)
    return None
