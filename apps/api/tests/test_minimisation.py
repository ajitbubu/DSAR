"""Post-closure minimisation (decision D-12)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.domain.minimisation.service import minimise_due
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.db import TenantContext, tenant_session
from tests import test_access_a3, test_closure
from tests.test_access_a2 import view
from tests.test_access_a3 import ask_code, reference
from tests.test_discovery import case_ready_for_discovery
from tests.test_retention import place

# Fixtures reused from the access and closure suites.
approved_access = test_access_a3.approved_access
delivered = test_access_a3.delivered
closed = test_closure.closed

LATER = datetime.now(UTC) + timedelta(days=31)  # past the default 30-day grace period


def minimise(client: TestClient, tenant: uuid.UUID, now: datetime = LATER) -> tuple[int, int]:
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        return minimise_due(s, registry=PolicyRegistry(), store=state.services.blob_store, now=now)


def one(engine: Engine, sql: str, rid: uuid.UUID) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(sql), {"r": rid}).one()


def test_nothing_is_minimised_inside_the_grace_period(client: TestClient, delivered) -> None:
    assert minimise(client, delivered["tenant"], datetime.now(UTC)) == (0, 0)
    assert minimise(client, delivered["tenant"], datetime.now(UTC) + timedelta(days=29)) == (0, 0)


def test_identifiers_and_blobs_are_shredded_after_the_grace_period(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    rid, tenant = delivered["rid"], delivered["tenant"]
    store = client.app.state.services.blob_store  # type: ignore[attr-defined]
    export_key = one(
        migrator_engine, "SELECT object_key FROM disclosure_export WHERE request_id = :r", rid
    )[0]
    evidence_key = one(
        migrator_engine, "SELECT object_key FROM evidence_artifact WHERE request_id = :r", rid
    )[0]
    assert export_key in store.objects

    assert minimise(client, tenant) == (1, 0)
    assert minimise(client, tenant) == (0, 0)  # idempotent

    req = one(
        migrator_engine,
        "SELECT enc_full_name, enc_submitted_identifiers, minimised_at, data_principal_id "
        "FROM privacy_request WHERE id = :r",
        rid,
    )
    assert req[0] is None and req[1] is None and req[2] is not None
    principal = one(
        migrator_engine,
        "SELECT enc_identifiers, bidx_email, bidx_phone, minimised_at FROM data_principal "
        "WHERE id = :r",
        req[3],
    )
    assert principal[:3] == (None, None, None) and principal[3] is not None
    counts = one(
        migrator_engine,
        "SELECT (SELECT count(*) FROM request_identifier WHERE request_id = :r),"
        " (SELECT count(*) FROM request_right WHERE request_id = :r AND enc_details IS NOT NULL),"
        " (SELECT count(*) FROM dp_session WHERE request_id = :r AND revoked_at IS NULL),"
        " (SELECT count(*) FROM disclosure_export WHERE request_id = :r AND purged_at IS NULL),"
        " (SELECT count(*) FROM access_report WHERE request_id = :r AND purged_at IS NULL)",
        rid,
    )
    assert tuple(counts) == (0, 0, 0, 0, 0)

    # Blobs holding exported content are gone; the evidence package (masked only) stays.
    assert export_key not in store.objects
    assert not any(str(delivered["report_id"]) in k for k in store.objects)
    assert evidence_key in store.objects

    details = one(
        migrator_engine,
        "SELECT details FROM audit_event WHERE object_id = :r AND action = 'request.minimised'",
        rid,
    )[0]
    assert details["principal_shredded"] is True
    assert "priya" not in str(details).lower()
    # Regression: ISSUE-003 — audit redaction blanked the deleted-identifier count
    # Found by /qa on 2026-10-02
    # Report: .gstack/qa-reports/run-20261002T184419Z/qa-report-dsar-2026-10-02.md
    assert "[REDACTED]" not in details.values()


def test_a_minimised_case_behaves_like_no_match(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    ref = reference(migrator_engine, delivered["rid"])
    assert minimise(client, delivered["tenant"]) == (1, 0)
    otp = client.app.state.otp_provider  # type: ignore[attr-defined]
    r = ask_code(client, delivered["tenant"], ref)
    assert r.status_code == 202  # same answer as for an unknown request...
    assert otp.peek(uuid.UUID(r.json()["challengeId"])) is None  # ...and no code sent
    staff = view(client, delivered)  # the staff view still opens without the export blob
    assert staff.status_code == 200 and staff.json()["records"] == []
    # Regression: ISSUE-002 — the case overview couldn't tell "shredded" from "not resolved yet"
    # Found by /qa on 2026-10-02
    # Report: .gstack/qa-reports/run-20261002T184419Z/qa-report-dsar-2026-10-02.md
    detail = client.get(f"/v1/cases/{delivered['rid']}", headers=delivered["analyst"]).json()
    assert detail["identifiers"] == [] and detail["minimised_at"] is not None


def test_a_legal_hold_blocks_minimisation_until_released(
    client: TestClient, closed, migrator_engine: Engine
) -> None:
    rid, tenant = closed["rid"], closed["tenant"]
    hold = place(client, closed["analyst"], scope="CASE", case_id=str(rid))
    assert hold.status_code == 201, hold.text
    assert minimise(client, tenant) == (0, 1)
    assert one(migrator_engine, "SELECT enc_full_name FROM privacy_request WHERE id = :r", rid)[0]
    release = client.post(f"/v1/legal-holds/{hold.json()['id']}/release", headers=closed["analyst"])
    assert release.status_code == 200
    assert minimise(client, tenant) == (1, 0)


def test_a_hold_on_a_record_type_the_case_touched_also_blocks(client: TestClient, closed) -> None:
    hold = place(client, closed["analyst"], scope="RECORD_TYPE", scope_ref="crm.invoice")
    assert hold.status_code == 201, hold.text
    assert minimise(client, closed["tenant"]) == (0, 1)


def test_the_principal_is_kept_while_another_of_their_requests_is_open(
    client: TestClient, closed, migrator_engine: Engine
) -> None:
    open_rid = case_ready_for_discovery(client, closed["tenant"])  # same requester, new case
    assert minimise(client, closed["tenant"]) == (1, 0)
    principal = one(
        migrator_engine,
        "SELECT p.enc_identifiers, p.bidx_email FROM data_principal p "
        "JOIN privacy_request r ON r.data_principal_id = p.id WHERE r.id = :r",
        open_rid,
    )
    assert principal[0] is not None and principal[1] is not None
    assert (
        one(
            migrator_engine,
            "SELECT count(*) FROM request_identifier WHERE request_id = :r",
            open_rid,
        )[0]
        > 0
    )
