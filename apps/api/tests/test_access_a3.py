"""Right to Access, milestone A3: report delivery to the requester (docs/milestones-access.md)."""

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.domain.cases.lifecycle import CaseStatus
from idprivacy.domain.communications import service as communications
from idprivacy.domain.disclosure import report as access_report
from idprivacy.domain.evidence import package as evidence
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.policy.workflow import GuardFailed, fire
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from tests.conftest import bff, make_settings, tenant_slug
from tests.test_access_a2 import export, record, register_all, submit, view
from tests.test_approvals import decide
from tests.test_closure import close
from tests.test_retention import status_of

EMAIL = "priya.sharma@example.in"
WITHHELD_VALUES = ("Pune", "Complaint letter")  # the contact's city and the withheld file
SESSIONS = "/v1/public/sessions"
REPORT = "/v1/public/case/report"


def _approval_id(engine: Engine, rid: uuid.UUID) -> uuid.UUID:
    with engine.connect() as conn:
        return conn.execute(  # type: ignore[no-any-return]
            text(
                "SELECT id FROM approval WHERE request_id = :r AND outcome = 'APPROVED' "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"r": rid},
        ).scalar_one()


@pytest.fixture
def approved_access(client: TestClient, review, migrator_engine: Engine) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    """Approved with the contact's city and the whole document withheld."""
    export(client, review)
    register_all(client, review)
    v = view(client, review).json()
    eid = v["export"]["id"]
    for match, field in (
        (record(v, "crm.contact")["match_id"], "city"),
        (record(v, "docs.file")["match_id"], None),
    ):
        r = client.post(
            f"/v1/cases/{review['rid']}/disclosure/exclusions",
            json={
                "export_id": eid,
                "data_match_id": match,
                "field_name": field,
                "action": "EXCLUDE",
                "reason_code": "THIRD_PARTY_DATA",
            },
            headers=review["analyst"],
        )
        assert r.status_code == 200, r.text
    assert submit(client, review, migrator_engine).status_code == 200
    assert decide(client, review["rid"], review["approver"]).status_code == 201
    assert status_of(migrator_engine, review["rid"])[0] == "FULFILMENT_IN_PROGRESS"
    return {**review, "approval_id": _approval_id(migrator_engine, review["rid"])}


def build(client: TestClient, ctx: dict[str, Any]) -> uuid.UUID | None:
    state = client.app.state  # type: ignore[attr-defined]
    return access_report.build(
        state.app_engine,
        tenant_id=ctx["tenant"],
        request_id=ctx["rid"],
        approval_id=ctx["approval_id"],
        store=state.services.blob_store,
        cipher=state.cipher,
        registry=PolicyRegistry(),
        settings=state.settings,
    )


def deliver(client: TestClient, ctx: dict[str, Any]) -> dict[str, Any]:
    """What the worker does: report, evidence package (REPORT_READY), then respond and close."""
    state = client.app.state  # type: ignore[attr-defined]
    report_id = build(client, ctx)
    assert report_id is not None
    artifact = evidence.generate(
        state.app_engine,
        tenant_id=ctx["tenant"],
        request_id=ctx["rid"],
        store=state.services.blob_store,
        registry=PolicyRegistry(),
        cipher=state.cipher,
        from_status=CaseStatus.FULFILMENT_IN_PROGRESS,
        event="REPORT_READY",
    )
    assert artifact is not None
    notifier = communications.MockNotificationProvider()
    assert close(client, ctx["tenant"], ctx["rid"], notifier) is True
    return {**ctx, "report_id": report_id, "artifact": artifact, "notifier": notifier}


@pytest.fixture
def delivered(client: TestClient, approved_access) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    return deliver(client, approved_access)


def reference(engine: Engine, rid: uuid.UUID) -> str:
    with engine.connect() as conn:
        return conn.execute(  # type: ignore[no-any-return]
            text("SELECT display_id FROM privacy_request WHERE id = :r"), {"r": rid}
        ).scalar_one()


def ask_code(client: TestClient, tenant: uuid.UUID, ref: str, email: str = EMAIL) -> Any:
    return client.post(
        SESSIONS,
        json={
            "intakeSlug": tenant_slug(tenant),
            "reference": ref,
            "contact": {"channel": "EMAIL", "value": email},
        },
        headers=bff(ip=f"198.19.{uuid.uuid4().int % 250}.2"),
    )


def sign_in(client: TestClient, tenant: uuid.UUID, ref: str) -> str:
    r = ask_code(client, tenant, ref)
    assert r.status_code == 202, r.text
    cid = r.json()["challengeId"]
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    assert code is not None
    c = client.post(f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff())
    assert c.status_code == 200, c.text
    return c.json()["sessionToken"]  # type: ignore[no-any-return]


def dp(token: str) -> dict[str, str]:
    return bff(**{"X-DP-Session": token})


# ---------- Building the report --------------------------------------------------------


def test_the_report_leaves_out_withheld_content_and_is_stored_encrypted(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    store = client.app.state.services.blob_store  # type: ignore[attr-defined]
    objects = [
        data for key, (data, _) in store.objects.items() if str(delivered["report_id"]) in key
    ]
    assert len(objects) == 2
    for data in objects:
        assert b"Priya Sharma" not in data and b"Delivery" not in data  # not plaintext

    token = sign_in(client, delivered["tenant"], reference(migrator_engine, delivered["rid"]))
    doc = client.get(f"{REPORT}/json", headers=dp(token)).json()
    assert [r["record_type"] for r in doc["records"]] == ["crm.contact", "crm.invoice"]
    contact = {f["label"]: f["value"] for f in doc["records"][0]["fields"]}
    assert contact["Name"] == "Priya Sharma" and "City" not in contact
    assert doc["withheld"] == {
        "records": 1,
        "fields": 1,
        "reasons": ["Contains another person's personal data"],
    }
    assert {p["source"] for p in doc["processing"]} == {"CRM", "DOCS"}
    for value in WITHHELD_VALUES:
        assert value not in json.dumps(doc)
        assert value not in client.get(f"{REPORT}/html", headers=dp(token)).text
    assert status_of(migrator_engine, delivered["rid"])[0] == "CLOSED"


def test_build_is_idempotent_per_approval(client: TestClient, approved_access) -> None:
    first = build(client, approved_access)
    assert first is not None and build(client, approved_access) == first


def test_report_ready_needs_a_stored_report(client: TestClient, approved_access) -> None:
    state = client.app.state  # type: ignore[attr-defined]
    with (
        pytest.raises(GuardFailed),
        tenant_session(state.app_engine, TenantContext(approved_access["tenant"])) as s,
    ):
        case = s.get(PrivacyRequest, approved_access["rid"])
        assert case is not None
        fire(s, case, "REPORT_READY", actor=access_report.ACTOR, registry=PolicyRegistry())


def test_html_escapes_every_value() -> None:
    doc = access_report.assemble(
        content={
            "records": [
                {
                    "match_id": str(uuid.uuid4()),
                    "connector_id": "c",
                    "record_type": "x<y>",
                    "fields": [
                        {
                            "name": "n",
                            "label": "<b>L</b>",
                            "category": "c",
                            "value": "<script>x</script>",
                        }
                    ],
                }
            ]
        },
        excluded={},
        processing=[{"source": "S&P", "purposes": ["<i>p</i>"], "recipients": []}],
        source_names={},
        reason_labels={},
        reference="DPR-2026-ABCDEF",
        controller="Acme <Retail>",
        generated_at=datetime.now(UTC),
        available_until=datetime.now(UTC),
    )
    out = access_report.render_html(doc)
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "<b>L</b>" not in out and "Acme &lt;Retail&gt;" in out and "S&amp;P" in out


def test_completion_message_and_evidence_carry_no_exported_values(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    assert len(delivered["notifier"].sent) == 1
    with migrator_engine.connect() as conn:
        text_sent = conn.execute(
            text("SELECT public_text FROM communication WHERE request_id = :r"),
            {"r": delivered["rid"]},
        ).scalar_one()
    assert "copy of the personal data" in text_sent and "2 records" in text_sent
    assert "withheld 2 items" in text_sent
    for value in ("Priya Sharma", *WITHHELD_VALUES):
        assert value not in text_sent

    store = client.app.state.services.blob_store  # type: ignore[attr-defined]
    with migrator_engine.connect() as conn:
        key, json_sha = conn.execute(
            text(
                "SELECT e.object_key, r.json_sha256 FROM evidence_artifact e "
                "JOIN access_report r ON r.request_id = e.request_id WHERE e.id = :a"
            ),
            {"a": delivered["artifact"]},
        ).one()
    blob = store.objects[key][0]
    zf = zipfile.ZipFile(io.BytesIO(blob))
    d = json.loads(zf.read("disclosure.json"))
    assert d["report"]["json_sha256"] == json_sha
    assert {x["reason_code"] for x in d["exclusions"]} == {"THIRD_PARTY_DATA"}
    everything = b"".join(zf.read(n) for n in zf.namelist())
    for value in ("Priya Sharma", *WITHHELD_VALUES):
        assert value.encode() not in everything


# ---------- Downloading ----------------------------------------------------------------


def test_downloads_need_a_live_session_for_that_request(
    client: TestClient, delivered, evaluated, migrator_engine: Engine
) -> None:
    ref = reference(migrator_engine, delivered["rid"])
    assert client.get(f"{REPORT}/json", headers=bff()).status_code == 401
    assert client.get(f"{REPORT}/json", headers=dp("x" * 43)).status_code == 401
    assert client.get(f"{REPORT}/json").status_code in (401, 403)  # not via the BFF

    token = sign_in(client, delivered["tenant"], ref)
    j = client.get(f"{REPORT}/json", headers=dp(token))
    assert j.status_code == 200
    assert j.headers["content-disposition"] == f'attachment; filename="{ref}-my-data.json"'
    assert j.headers["cache-control"] == "no-store"
    assert j.headers["x-content-type-options"] == "nosniff"
    h = client.get(f"{REPORT}/html", headers=dp(token))
    assert h.status_code == 200 and "sandbox" in h.headers["content-security-policy"]
    assert client.get(f"{REPORT}/pdf", headers=dp(token)).status_code == 422

    # Another requester's live session (an erasure case, another tenant) finds nothing.
    other_tenant, other_rid = evaluated
    other = sign_in(client, other_tenant, reference(migrator_engine, other_rid))
    assert client.get(f"{REPORT}/json", headers=dp(other)).status_code == 404

    with migrator_engine.connect() as conn:
        n = conn.execute(
            text(
                "SELECT count(*) FROM audit_event WHERE object_id = :r "
                "AND action = 'access_report.downloaded'"
            ),
            {"r": delivered["report_id"]},
        ).scalar_one()
    assert n == 2


def test_the_download_limit_and_expiry_give_410(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    token = sign_in(client, delivered["tenant"], reference(migrator_engine, delivered["rid"]))
    limit = client.app.state.settings.access_report_max_downloads  # type: ignore[attr-defined]
    for _ in range(limit):
        assert client.get(f"{REPORT}/json", headers=dp(token)).status_code == 200
    assert client.get(f"{REPORT}/json", headers=dp(token)).status_code == 410
    status = client.get("/v1/public/case", headers=dp(token)).json()
    assert status["report"]["available"] is False and status["report"]["downloadsLeft"] == 0

    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE access_report SET download_count = 0, "
                "expires_at = now() - interval '1 day' "
                "WHERE id = :r"
            ),
            {"r": delivered["report_id"]},
        )
    assert client.get(f"{REPORT}/json", headers=dp(token)).status_code == 410


def test_status_shows_the_report_to_the_requester(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    token = sign_in(client, delivered["tenant"], reference(migrator_engine, delivered["rid"]))
    body = client.get("/v1/public/case", headers=dp(token)).json()
    assert body["status"] == "Closed"
    assert body["report"]["available"] is True
    assert body["report"]["records"] == 2 and body["report"]["withheld"] == 2
    assert "copy of the personal data" in body["completionResponse"]


def test_purge_deletes_expired_report_objects(
    client: TestClient, delivered, migrator_engine: Engine, app_engine: Engine
) -> None:
    store = client.app.state.services.blob_store  # type: ignore[attr-defined]
    rid = str(delivered["report_id"])
    assert sum(rid in k for k in store.objects) == 2
    with tenant_session(app_engine, TenantContext(delivered["tenant"])) as s:
        assert access_report.purge_due(s, store=store) == 0  # still valid
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE access_report SET expires_at = now() - interval '1 minute' WHERE id = :r"),
            {"r": rid},
        )
    with tenant_session(app_engine, TenantContext(delivered["tenant"])) as s:
        assert access_report.purge_due(s, store=store) == 1
    assert sum(rid in k for k in store.objects) == 0
    token = sign_in(client, delivered["tenant"], reference(migrator_engine, delivered["rid"]))
    assert client.get(f"{REPORT}/json", headers=dp(token)).status_code == 410


def test_the_app_role_can_only_change_the_counter_and_purge_marker(
    delivered, app_engine: Engine
) -> None:
    from sqlalchemy.exc import DBAPIError

    for sql in (
        "UPDATE access_report SET max_downloads = 100",
        "UPDATE access_report SET expires_at = now() + interval '1 year'",
        "DELETE FROM access_report",
    ):
        with (
            pytest.raises(DBAPIError),
            tenant_session(app_engine, TenantContext(delivered["tenant"])) as s,
        ):
            s.execute(text(sql))


# ---------- Returning sign-in -----------------------------------------------------------


def test_sign_in_never_reveals_whether_a_request_exists(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    ref = reference(migrator_engine, delivered["rid"])
    tenant = delivered["tenant"]
    otp = client.app.state.otp_provider  # type: ignore[attr-defined]
    cases = [
        ask_code(client, tenant, ref),  # real
        ask_code(client, tenant, ref, "someone.else@example.in"),  # wrong contact
        ask_code(client, tenant, "DPR-2026-ZZZZZZ"),  # no such request
    ]
    assert [r.status_code for r in cases] == [202, 202, 202]
    assert {tuple(sorted(r.json())) for r in cases} == {
        ("challengeId", "destinationHint", "expiresAt")
    }
    sent = [otp.peek(uuid.UUID(r.json()["challengeId"])) is not None for r in cases]
    assert sent == [True, False, False]
    assert ask_code(client, tenant, "not-a-reference").status_code == 422


def test_a_locked_sign_in_leaves_the_case_alone(
    client: TestClient, delivered, migrator_engine: Engine
) -> None:
    before = status_of(migrator_engine, delivered["rid"])
    r = ask_code(client, delivered["tenant"], reference(migrator_engine, delivered["rid"]))
    cid = r.json()["challengeId"]
    for _ in range(make_settings().otp_max_attempts):
        client.post(
            f"/v1/public/verifications/{cid}/confirm", json={"code": "000000"}, headers=bff()
        )
    assert status_of(migrator_engine, delivered["rid"]) == before
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    c = client.post(f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff())
    assert c.status_code == 429  # locked, even with the right code


def test_sign_in_is_not_offered_before_a_request_is_verified(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    from tests.test_public_intake import SUBMIT, form

    tenant = make_tenant()
    r = client.post(
        SUBMIT,
        json=form(tenant_slug(tenant), contact={"channel": "EMAIL", "value": EMAIL}),
        headers=bff(ip="198.19.250.9"),
    )
    ref = r.json()["displayId"]
    signin = ask_code(client, tenant, ref)
    assert signin.status_code == 202
    peek = client.app.state.otp_provider.peek  # type: ignore[attr-defined]
    assert peek(uuid.UUID(signin.json()["challengeId"])) is None
