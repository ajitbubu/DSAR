"""Completion response to the Data Principal, then case closure (M8).

The message says what happened without repeating any personal data: counts per
outcome, retention reasons from the pack's own labels, and the reference number.
"""

import hashlib
from collections import Counter
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.config import DEV_ENVIRONMENTS, Settings
from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.disclosure.report import latest_report
from idprivacy.domain.intake import service as intake
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import SystemActor, fire
from idprivacy.domain.retention.service import current_decisions
from idprivacy.domain.verification.service import latest_tasks
from idprivacy.platform.crypto import FieldCipher
from idprivacy.platform.models import AccessReport, Communication, PrivacyRequest

ACTOR = SystemActor("system:communications")
TEMPLATE = "erasure.completed"


class NotificationProvider(Protocol):
    name: str

    def send(self, *, channel: str, destination: str, text: str) -> None: ...


class MockNotificationProvider:
    """Dev/test only: records that a message was sent, without the destination."""

    name = "mock"

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, *, channel: str, destination: str, text: str) -> None:
        self.sent.append((channel, hashlib.sha256(text.encode()).hexdigest()))


def build_notifier(settings: Settings) -> NotificationProvider:
    if settings.notification_provider == "mock":
        if settings.env not in DEV_ENVIRONMENTS:
            raise RuntimeError("mock notification provider is only permitted in local/test")
        return MockNotificationProvider()
    raise RuntimeError(f"unsupported notification provider {settings.notification_provider!r}")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def compose_access(request: PrivacyRequest, report: AccessReport) -> str:
    """No personal data: counts and dates only. The content is in the report itself."""
    parts = [
        f"Your copy of the personal data we hold about you (request {request.display_id}) "
        "is ready.",
        f"It covers {_plural(report.record_count, 'record', 'records')}.",
    ]
    withheld = report.withheld_records + report.withheld_fields
    if withheld:
        parts.append(
            f"We withheld {_plural(withheld, 'item', 'items')} that include other people's "
            "personal data or are otherwise exempt."
        )
    parts.append(
        "Download it from your request page, signing in again with your reference if "
        f"needed, before {report.expires_at.strftime('%d %B %Y')}. You can download it "
        f"up to {report.max_downloads} times."
    )
    return " ".join(parts)[:2000]


def compose(session: Session, request: PrivacyRequest, registry: PolicyRegistry) -> str:
    report = latest_report(session, request.id)
    if report is not None:
        return compose_access(request, report)
    assert request.policy_pack_id is not None
    pack = registry.by_id(session, request.policy_pack_id).pack
    labels = {e.code: e.label for e in pack.exception_codes}
    tasks = latest_tasks(session, request.id)
    decisions = current_decisions(session, request.id)
    done = Counter(t.action for t in tasks if t.status == "SUCCEEDED")
    kept = Counter(
        labels.get(d.exception_code or "", "a documented exception")
        for d in decisions.values()
        if d.decision == "RETAIN"
    )
    held = sum(
        1 for t in tasks if t.status == "SKIPPED" and (t.skip_reason or "").startswith("LEGAL_HOLD")
    )
    parts = [
        f"We've completed your erasure request {request.display_id} on "
        f"{datetime.now(UTC).strftime('%d %B %Y')}."
    ]
    if done["DELETE"]:
        parts.append(f"{_plural(done['DELETE'], 'record was', 'records were')} deleted.")
    if done["ANONYMIZE"]:
        parts.append(f"{_plural(done['ANONYMIZE'], 'record was', 'records were')} anonymised.")
    if done["RESTRICT"]:
        parts.append(
            f"{_plural(done['RESTRICT'], 'record was', 'records were')} restricted "
            "from further use."
        )
    for label, n in sorted(kept.items()):
        parts.append(f"{_plural(n, 'record was', 'records were')} kept: {label.rstrip('.')}.")
    if held:
        parts.append(
            f"{_plural(held, 'record is', 'records are')} under a legal hold and "
            "will be reviewed when it ends."
        )
    if not tasks:
        parts.append("We found no personal data about you in our systems.")
    return " ".join(parts)[:2000]


def respond_and_close(
    session: Session,
    *,
    request_id: UUID,
    registry: PolicyRegistry,
    cipher: FieldCipher,
    notifier: NotificationProvider,
) -> bool:
    """Send the completion response once, then close. Idempotent."""
    request = session.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == request_id).with_for_update()
    ).scalar_one_or_none()
    if request is None or request.status != CaseStatus.EVIDENCE_GENERATED:
        return False
    text = compose(session, request, registry)
    channel, destination = intake.contact_for_request(cipher, request)
    notifier.send(channel=channel, destination=destination, text=text)
    session.add(
        Communication(
            tenant_id=request.tenant_id,
            request_id=request.id,
            template_code=TEMPLATE,
            channel=channel,
            provider=notifier.name,
            status="SENT",
            public_text=text,
            body_sha256=hashlib.sha256(text.encode()).hexdigest(),
        )
    )
    session.flush()
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref=ACTOR.ref,
        action="communication.sent",
        object_type="privacy_request",
        object_id=request.id,
        details={"template": TEMPLATE, "channel": channel, "provider": notifier.name},
    )
    fire(session, request, "RESPOND", actor=ACTOR, registry=registry)
    fire(session, request, "CLOSE", actor=ACTOR, registry=registry)
    request.closed_at = datetime.now(UTC)
    return True


def completion_text(session: Session, request_id: UUID) -> str | None:
    row = session.execute(
        select(Communication.public_text).where(
            Communication.request_id == request_id, Communication.template_code == TEMPLATE
        )
    ).scalar_one_or_none()
    return row
