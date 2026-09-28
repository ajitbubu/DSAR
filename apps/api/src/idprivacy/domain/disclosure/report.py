"""The requester's access report (docs/milestones-access.md, A3).

1. ``plan``: when the disclosure is approved, start fulfilment and queue the build.
2. ``build``: apply the approved exclusions to the export, add the processing summary,
   render JSON and HTML, encrypt each under the tenant key and store them privately.
   The database gets hashes and counts only.
3. ``download``: the requester fetches it through a live tracking session, within its
   availability window and download limit (decision D-25). Every download is audited.
4. ``purge_due``: expired or used-up reports have their objects deleted.
"""

import hashlib
import html
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from idprivacy.config import Settings
from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.disclosure import service as disclosure
from idprivacy.domain.disclosure.register import current_register
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.platform import outbox
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import (
    AccessReport,
    Approval,
    ConnectorConfig,
    PrivacyRequest,
    Tenant,
)
from idprivacy.platform.storage import BlobStore, object_key

ACTOR = SystemActor("system:access_report")
FORMAT_VERSION = 1
FORMATS = {
    "json": ("application/json", "json"),
    "html": ("text/html; charset=utf-8", "html"),
}


def _context(report_id: UUID, fmt: str) -> str:
    return f"access_report:{report_id}:{fmt}"


def plan(
    session: Session, *, request: PrivacyRequest, approval: Approval, registry: PolicyRegistry
) -> None:
    """Called in the approval transaction for a case with a disclosure."""
    fire(session, request, "START_FULFILMENT", actor=ACTOR, registry=registry)
    outbox.enqueue(
        session,
        tenant_id=request.tenant_id,
        topic="case.report_requested",
        payload={"request_id": request.id, "approval_id": approval.id},
    )
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR.ref,
        action="access_report.planned",
        object_type="privacy_request",
        object_id=request.id,
        details={"approval_id": str(approval.id)},
    )


def report_for_approval(session: Session, approval_id: UUID) -> AccessReport | None:
    return session.execute(
        select(AccessReport).where(AccessReport.approval_id == approval_id)
    ).scalar_one_or_none()


def latest_report(session: Session, request_id: UUID) -> AccessReport | None:
    return session.execute(
        select(AccessReport)
        .where(AccessReport.request_id == request_id)
        .order_by(AccessReport.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def assemble(
    *,
    content: dict[str, Any],
    excluded: dict[disclosure.ExclusionKey, Any],
    processing: list[dict[str, Any]],
    source_names: dict[str, str],
    reason_labels: dict[str, str],
    reference: str,
    controller: str,
    generated_at: datetime,
    available_until: datetime,
) -> dict[str, Any]:
    """Pure: the report as the requester will see it. Withheld content never enters it."""
    records, withheld_records, withheld_fields, reasons = [], 0, 0, set()
    for r in content["records"]:
        mid = UUID(r["match_id"])
        if (mid, None) in excluded:
            withheld_records += 1
            reasons.add(excluded[(mid, None)].reason_code)
            continue
        fields = []
        for f in r["fields"]:
            if (mid, f["name"]) in excluded:
                withheld_fields += 1
                reasons.add(excluded[(mid, f["name"])].reason_code)
                continue
            fields.append({"label": f["label"], "category": f["category"], "value": f["value"]})
        records.append(
            {
                "source": source_names.get(r["connector_id"], r["connector_id"]),
                "record_type": r["record_type"],
                "fields": fields,
            }
        )
    return {
        "format_version": FORMAT_VERSION,
        "reference": reference,
        "controller": controller,
        "generated_at": generated_at.isoformat(),
        "available_until": available_until.isoformat(),
        "records": records,
        "withheld": {
            "records": withheld_records,
            "fields": withheld_fields,
            "reasons": sorted(reason_labels.get(c, c) for c in reasons),
        },
        "processing": processing,
    }


def render_html(doc: dict[str, Any]) -> str:
    """Self-contained, script-free, accessible HTML. Every value is escaped."""
    e = html.escape

    def value(v: Any) -> str:
        return "—" if v is None else e(str(v))

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Your data · {e(doc['reference'])}</title>",
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;"
        "padding:0 1rem;color:#1b1f24}table{border-collapse:collapse;width:100%;margin:.5rem 0"
        " 1.5rem}th,td{border:1px solid #c9ced6;padding:.4rem .6rem;text-align:left;"
        "vertical-align:top}th{background:#f2f4f7}caption{text-align:left;font-weight:600;"
        "padding:.25rem 0}</style></head><body>",
        f"<h1>Your personal data held by {e(doc['controller'])}</h1>",
        f"<p>Request reference <strong>{e(doc['reference'])}</strong>. Prepared "
        f"{e(doc['generated_at'][:10])}; available until {e(doc['available_until'][:10])}.</p>",
        "<h2>What we hold about you</h2>",
    ]
    if not doc["records"]:
        parts.append("<p>We found no personal data about you to disclose.</p>")
    for i, r in enumerate(doc["records"], 1):
        parts.append(
            f"<table><caption>Record {i}: {e(r['record_type'])} ({e(r['source'])})</caption>"
            '<thead><tr><th scope="col">Item</th><th scope="col">Value</th>'
            '<th scope="col">Category</th></tr></thead><tbody>'
        )
        for f in r["fields"]:
            parts.append(
                f'<tr><th scope="row">{e(f["label"])}</th><td>{value(f["value"])}</td>'
                f"<td>{e(f['category'])}</td></tr>"
            )
        parts.append("</tbody></table>")
    w = doc["withheld"]
    if w["records"] or w["fields"]:
        parts.append(
            f"<h2>What we withheld</h2><p>{w['records']} record(s) and {w['fields']} item(s) were "
            f"withheld: {e('; '.join(w['reasons']))}.</p>"
        )
    parts.append("<h2>How your data is used and shared</h2><ul>")
    for p in doc["processing"]:
        shared = ", ".join(f"{r['name']} ({r['kind'].lower()})" for r in p["recipients"])
        parts.append(
            f"<li><strong>{e(p['source'])}</strong>: {e('; '.join(p['purposes']))}"
            + (f". Shared with {e(shared)}" if shared else "")
            + "</li>"
        )
    parts.append("</ul></body></html>")
    return "".join(parts)


def build(
    engine: Engine,
    *,
    tenant_id: UUID,
    request_id: UUID,
    approval_id: UUID,
    store: BlobStore,
    cipher: FieldCipher,
    registry: PolicyRegistry,
    settings: Settings,
) -> UUID | None:
    """Build and store the report for an approval. Idempotent per approval."""
    ctx = TenantContext(tenant_id)
    with tenant_session(engine, ctx) as s:
        request = s.get(PrivacyRequest, request_id)
        if request is None or request.status != CaseStatus.FULFILMENT_IN_PROGRESS:
            return None
        existing = report_for_approval(s, approval_id)
        if existing is not None:
            return existing.id
        export = disclosure.latest_export(s, request_id)
        assert export is not None and export.status == "READY"
        content = disclosure.load_content(export, cipher=cipher, store=store)
        excluded = disclosure.current_exclusions(s, export.id)
        register = current_register(s)
        names = dict(
            s.execute(select(ConnectorConfig.connector_id, ConnectorConfig.display_name)).all()
        )
        processing = [
            {
                "source": names.get(c, c),
                "purposes": list(register[c].purposes),
                "recipients": list(register[c].recipients),
            }
            for c in disclosure.case_connectors(s, request_id)
            if c in register
        ]
        assert request.policy_pack_id is not None
        pack = registry.by_id(s, request.policy_pack_id).pack
        tenant = s.get(Tenant, tenant_id)
        assert tenant is not None
        now = datetime.now(UTC)
        until = now + timedelta(days=settings.access_report_ttl_days)
        doc = assemble(
            content=content,
            excluded=excluded,
            processing=processing,
            source_names=names,
            reason_labels={c.code: c.label for c in pack.exception_codes},
            reference=request.display_id,
            controller=tenant.name,
            generated_at=now,
            available_until=until,
        )
        export_id = export.id

    report_id = uuid4()
    bodies = {
        "json": json.dumps(doc, indent=2, ensure_ascii=False).encode(),
        "html": render_html(doc).encode(),
    }
    keys = {}
    for fmt, body in bodies.items():
        keys[fmt] = object_key(tenant_id, request_id, report_id, f"{fmt}.enc")
        token = cipher.encrypt(tenant_id, _context(report_id, fmt), body.decode())
        store.put(keys[fmt], token.encode(), "application/octet-stream")

    with tenant_session(engine, ctx) as s:
        s.execute(
            select(PrivacyRequest.id).where(PrivacyRequest.id == request_id).with_for_update()
        )
        if (existing := report_for_approval(s, approval_id)) is not None:
            return existing.id  # a concurrent run won; our objects are orphans
        try:
            with s.begin_nested():
                s.add(
                    AccessReport(
                        id=report_id,
                        tenant_id=tenant_id,
                        request_id=request_id,
                        export_id=export_id,
                        approval_id=approval_id,
                        json_key=keys["json"],
                        html_key=keys["html"],
                        json_sha256=hashlib.sha256(bodies["json"]).hexdigest(),
                        html_sha256=hashlib.sha256(bodies["html"]).hexdigest(),
                        record_count=len(doc["records"]),
                        withheld_records=doc["withheld"]["records"],
                        withheld_fields=doc["withheld"]["fields"],
                        expires_at=until,
                        max_downloads=settings.access_report_max_downloads,
                    )
                )
        except IntegrityError:
            existing = report_for_approval(s, approval_id)
            assert existing is not None
            return existing.id
        audit.append(
            s,
            tenant_id=tenant_id,
            actor_type="SYSTEM",
            actor_ref=ACTOR.ref,
            action="access_report.generated",
            object_type="access_report",
            object_id=report_id,
            details={
                "request_id": str(request_id),
                "approval_id": str(approval_id),
                "json_sha256": hashlib.sha256(bodies["json"]).hexdigest(),
                "html_sha256": hashlib.sha256(bodies["html"]).hexdigest(),
                "records": len(doc["records"]),
                "withheld_records": doc["withheld"]["records"],
                "withheld_fields": doc["withheld"]["fields"],
                "available_until": until.isoformat(),
            },
        )
    return report_id


class ReportGone(Exception):
    """410: expired, download limit reached, or purged."""


@dataclass(frozen=True)
class Download:
    body: bytes
    media_type: str
    filename: str


def download(
    session: Session,
    *,
    request_id: UUID,
    fmt: str,
    cipher: FieldCipher,
    store: BlobStore,
) -> Download:
    """Raises LookupError (no report) or ReportGone. Counts and audits the download."""
    report = latest_report(session, request_id)
    if report is None:
        raise LookupError(request_id)
    now = datetime.now(UTC)
    n = session.execute(
        update(AccessReport)
        .where(
            AccessReport.id == report.id,
            AccessReport.purged_at.is_(None),
            AccessReport.expires_at > now,
            AccessReport.download_count < AccessReport.max_downloads,
        )
        .values(download_count=AccessReport.download_count + 1)
        .returning(AccessReport.download_count)
    ).scalar_one_or_none()
    if n is None:
        raise ReportGone(str(report.id))
    key, sha = (
        (report.json_key, report.json_sha256)
        if fmt == "json"
        else (report.html_key, report.html_sha256)
    )
    token = b"".join(store.stream(key)).decode()
    body = cipher.decrypt(report.tenant_id, _context(report.id, fmt), token).encode()
    if hashlib.sha256(body).hexdigest() != sha:
        raise disclosure.ContentIntegrityError(str(report.id))
    request = session.get(PrivacyRequest, request_id)
    assert request is not None
    audit.append(
        session,
        tenant_id=report.tenant_id,
        actor_type="DATA_PRINCIPAL",
        actor_ref=f"data_principal:{request_id}",
        action="access_report.downloaded",
        object_type="access_report",
        object_id=report.id,
        details={"format": fmt, "download": n, "max_downloads": report.max_downloads},
    )
    media, ext = FORMATS[fmt]
    return Download(body, media, f"{request.display_id}-my-data.{ext}")


def purge_due(session: Session, *, store: BlobStore, now: datetime | None = None) -> int:
    """Delete the objects of expired or used-up reports in the session's tenant."""
    now = now or datetime.now(UTC)
    due = (
        session.execute(
            select(AccessReport)
            .where(
                AccessReport.purged_at.is_(None),
                or_(
                    AccessReport.expires_at <= now,
                    AccessReport.download_count >= AccessReport.max_downloads,
                ),
            )
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )
    for r in due:
        store.delete(r.json_key)
        store.delete(r.html_key)
        session.execute(update(AccessReport).where(AccessReport.id == r.id).values(purged_at=now))
        audit.append(
            session,
            tenant_id=r.tenant_id,
            actor_type="SYSTEM",
            actor_ref=ACTOR.ref,
            action="access_report.purged",
            object_type="access_report",
            object_id=r.id,
            details={"downloads": r.download_count, "expired": r.expires_at <= now},
        )
    return len(due)
