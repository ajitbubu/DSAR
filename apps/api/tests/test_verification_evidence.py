"""Verification, reconciliation, evidence package, uploads (M7)."""

import hashlib
import io
import json
import uuid
import zipfile
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from idprivacy.domain.evidence import package as evidence
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.verification import service as verification
from tests.conftest import bearer
from tests.test_approvals import decide
from tests.test_fulfilment import run_all, tasks
from tests.test_retention import override, status_of, transition

ALL_PASS = {
    "crm:contact:c-1001": ("ABSENT", "PASS"),
    "crm:invoice:i-5001": ("PRESENT", "PASS"),
    "docs:file:d-3001": ("ABSENT", "PASS"),
}


def verify(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID, factory: Any) -> str | None:
    state = client.app.state  # type: ignore[attr-defined]
    return verification.run(
        state.app_engine,
        tenant_id=tenant,
        request_id=rid,
        factory=factory,
        registry=PolicyRegistry(),
        cipher=state.cipher,
    )


def generate(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID) -> uuid.UUID | None:
    state = client.app.state  # type: ignore[attr-defined]
    return evidence.generate(
        state.app_engine,
        tenant_id=tenant,
        request_id=rid,
        store=state.services.blob_store,
        registry=PolicyRegistry(),
        cipher=state.cipher,
    )


def results(engine: Engine, rid: uuid.UUID, round_no: int = 1) -> dict[str, tuple[str, str]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT m.source_record_ref, v.expected, v.outcome FROM verification_result v "
                "JOIN data_match m ON m.id = v.data_match_id WHERE v.request_id = :r "
                "AND v.round = :n"
            ),
            {"r": rid, "n": round_no},
        ).all()
    return {r[0]: (r[1], r[2]) for r in rows}


# ---------- Verification -------------------------------------------------------------


def test_successful_fulfilment_verifies(
    client: TestClient, fulfilled, connector_factory, migrator_engine: Engine
) -> None:
    tenant, rid = fulfilled["tenant"], fulfilled["rid"]
    assert verify(client, tenant, rid, connector_factory) == "PASS"
    assert results(migrator_engine, rid) == ALL_PASS
    assert status_of(migrator_engine, rid)[0] == "VERIFIED_COMPLETE"
    assert verify(client, tenant, rid, connector_factory) is None  # idempotent


@pytest.mark.parametrize(
    "expected, observed, rescan, ok",
    [
        ("ABSENT", "ABSENT", False, True),
        ("ABSENT", "ABSENT", True, False),
        ("ABSENT", "PRESENT", False, False),
        ("ANONYMIZED", "ANONYMIZED", False, True),
        ("ANONYMIZED", "ANONYMIZED", True, False),
        ("RESTRICTED", "RESTRICTED", True, True),
        ("PRESENT", "PRESENT", True, True),
        ("PRESENT", "ABSENT", False, False),
        ("PRESENT", "PRESENT", False, False),
        ("ABSENT", None, False, False),
    ],
)
def test_judge(expected: str, observed: str | None, rescan: bool, ok: bool) -> None:
    assert verification.judge(expected, observed, rescan) is ok


def test_lying_connector_is_caught_and_reconciled(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults", json={"account": "acme", "system": "crm", "fail_next": 0, "lie": True}
    )
    run_all(client, tenant, rid, connector_factory)
    assert tasks(migrator_engine, rid)["crm:contact:c-1001"]["status"] == "SUCCEEDED"  # claimed
    assert verify(client, tenant, rid, connector_factory) == "FAIL"
    assert results(migrator_engine, rid)["crm:contact:c-1001"] == ("ABSENT", "FAIL")
    assert status_of(migrator_engine, rid)[0] == "RECONCILIATION_REQUIRED"

    old_key = tasks(migrator_engine, rid)["crm:contact:c-1001"]["idempotency_key"]
    mock_connectors.post(
        "/__test__/faults", json={"account": "acme", "system": "crm", "fail_next": 0, "lie": False}
    )
    r = client.post(f"/v1/cases/{rid}/reconcile", headers=approved["analyst"])
    assert r.status_code == 202 and r.json() == {"tasks": 1}
    with migrator_engine.connect() as conn:
        rounds = conn.execute(
            text(
                "SELECT round, idempotency_key, status FROM fulfilment_task t JOIN data_match m "
                "ON m.id = t.data_match_id WHERE m.source_record_ref = 'crm:contact:c-1001' "
                "AND t.request_id = :r ORDER BY round"
            ),
            {"r": rid},
        ).all()
    assert [r.round for r in rounds] == [1, 2] and rounds[1].idempotency_key != old_key
    run_all(client, tenant, rid, connector_factory)
    assert verify(client, tenant, rid, connector_factory) == "PASS"
    assert results(migrator_engine, rid, 2) == ALL_PASS
    assert client.post(f"/v1/cases/{rid}/reconcile", headers=approved["analyst"]).status_code == 409


def test_permanently_failed_task_fails_verification(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 1, "status": 400},
    )
    run_all(client, tenant, rid, connector_factory)
    assert verify(client, tenant, rid, connector_factory) == "FAIL"
    assert results(migrator_engine, rid)["docs:file:d-3001"] == ("ABSENT", "FAIL")


def test_anonymise_and_restrict_are_verified(
    client: TestClient,
    evaluated,
    provision_user,
    make_token,
    connector_factory,
    migrator_engine: Engine,
) -> None:
    tenant, rid = evaluated
    _, a = provision_user(tenant, ["PRIVACY_ANALYST"])
    _, b = provision_user(tenant, ["APPROVER"])
    analyst, approver = bearer(make_token(a)), bearer(make_token(b))
    transition(client, rid, "BEGIN_REVIEW", analyst, migrator_engine)
    for ref, decision in (
        ("crm:contact:c-1001", "ANONYMIZE"),
        ("docs:file:d-3001", "RESTRICT"),
        ("crm:invoice:i-5001", "RETAIN"),
    ):
        assert (
            override(
                client,
                rid,
                ref,
                analyst,
                migrator_engine,
                decision=decision,
                exception_code="LEGAL_OBLIGATION",
            ).status_code
            == 201
        )
    transition(client, rid, "SUBMIT_FOR_APPROVAL", analyst, migrator_engine)
    assert decide(client, rid, approver).status_code == 201
    run_all(client, tenant, rid, connector_factory)
    assert verify(client, tenant, rid, connector_factory) == "PASS"
    assert results(migrator_engine, rid) == {
        "crm:contact:c-1001": ("ANONYMIZED", "PASS"),
        "docs:file:d-3001": ("RESTRICTED", "PASS"),
        "crm:invoice:i-5001": ("PRESENT", "PASS"),
    }


def test_verification_view_and_permissions(
    client: TestClient, fulfilled, connector_factory, provision_user, make_token, make_tenant
) -> None:
    tenant, rid = fulfilled["tenant"], fulfilled["rid"]
    verify(client, tenant, rid, connector_factory)
    view = client.get(f"/v1/cases/{rid}/verification", headers=fulfilled["analyst"]).json()
    assert view["latest_round"] == 1 and len(view["results"]) == 3
    _, other = provision_user(make_tenant(), ["AUDITOR"])
    assert (
        client.get(f"/v1/cases/{rid}/verification", headers=bearer(make_token(other))).status_code
        == 404
    )
    _, auditor = provision_user(tenant, ["AUDITOR"])
    assert (
        client.post(f"/v1/cases/{rid}/reconcile", headers=bearer(make_token(auditor))).status_code
        == 403
    )


# ---------- Evidence package ----------------------------------------------------------


def _zip(client: TestClient, packaged: dict[str, Any]) -> tuple[Any, zipfile.ZipFile]:
    r = client.get(
        f"/v1/cases/{packaged['rid']}/evidence/{packaged['artifact']}/content",
        headers=packaged["analyst"],
    )
    assert r.status_code == 200
    return r, zipfile.ZipFile(io.BytesIO(r.content))


def test_package_contents_and_hashes(client: TestClient, packaged, migrator_engine: Engine) -> None:
    r, zf = _zip(client, packaged)
    assert r.headers["content-disposition"].startswith('attachment; filename="evidence-DPR-')
    assert r.headers["x-content-type-options"] == "nosniff"
    names = set(zf.namelist())
    assert {
        "manifest.json",
        "manifest.sha256",
        "decisions.json",
        "approvals.json",
        "fulfilment.json",
        "connector_evidence.json",
        "verification_report.json",
        "audit_timeline.json",
    } <= names
    manifest_bytes = zf.read("manifest.json")
    manifest = json.loads(manifest_bytes)
    for entry in manifest["files"]:
        assert hashlib.sha256(zf.read(entry["name"])).hexdigest() == entry["sha256"]
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    assert zf.read("manifest.sha256").decode().split()[0] == manifest_sha
    assert hashlib.sha256(r.content).hexdigest() == r.headers["x-content-sha256"]

    with migrator_engine.connect() as conn:
        details = conn.execute(
            text(
                "SELECT details FROM audit_event WHERE action = 'evidence.package_generated' "
                "AND object_id = :a"
            ),
            {"a": packaged["artifact"]},
        ).scalar_one()
    assert details["manifest_sha256"] == manifest_sha  # anchored in the audit hash chain
    assert status_of(migrator_engine, packaged["rid"])[0] == "EVIDENCE_GENERATED"

    decisions = json.loads(zf.read("decisions.json"))
    retained = [
        d
        for d in decisions
        if d["record"] == "crm:invoice:i-5001" and d["source"] == "ANALYST_OVERRIDE"
    ]
    assert retained and "GST" in retained[0]["exception_reason"]
    report = json.loads(zf.read("verification_report.json"))
    assert {v["outcome"] for v in report} == {"PASS"}
    approvals = json.loads(zf.read("approvals.json"))
    assert approvals["decisions"][0]["approved_by"] != approvals["decisions"][0]["submitted_by"]


def test_package_contains_no_plaintext_personal_data(client: TestClient, packaged) -> None:
    _, zf = _zip(client, packaged)
    blob = b" ".join(zf.read(n) for n in zf.namelist()).decode().lower()
    for needle in ("priya", "sharma", "example.in", "+91987"):
        assert needle not in blob, needle
    assert "p•••@e•••.in" in blob


def test_audit_chain_still_verifies_after_packaging(
    client: TestClient, packaged, provision_user, make_token
) -> None:
    _, auditor = provision_user(packaged["tenant"], ["AUDITOR"])
    assert client.post("/v1/audit/verify", headers=bearer(make_token(auditor))).json()["ok"] is True


def test_downloads_are_audited_and_restricted(
    client: TestClient, packaged, provision_user, make_token, make_tenant, migrator_engine: Engine
) -> None:
    url = f"/v1/cases/{packaged['rid']}/evidence/{packaged['artifact']}/content"
    _zip(client, packaged)
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text(
                "SELECT count(*) FROM audit_event WHERE action = "
                "'evidence.downloaded' AND object_id = :a"
            ),
            {"a": packaged["artifact"]},
        ).scalar_one()
    assert n == 1
    _, admin = provision_user(packaged["tenant"], ["TENANT_ADMIN"])
    _, outsider = provision_user(make_tenant(), ["AUDITOR"])
    assert client.get(url, headers=bearer(make_token(admin))).status_code == 403
    assert client.get(url, headers=bearer(make_token(outsider))).status_code == 404
    assert (
        client.get(
            f"/v1/cases/{packaged['rid']}/evidence/{uuid.uuid4()}/content",
            headers=packaged["analyst"],
        ).status_code
        == 404
    )
    assert client.get(url).status_code == 401


def test_evidence_is_stored_under_an_opaque_private_key(
    client: TestClient, packaged, migrator_engine: Engine
) -> None:
    with migrator_engine.connect() as conn:
        key = conn.execute(
            text("SELECT object_key FROM evidence_artifact WHERE id = :a"),
            {"a": packaged["artifact"]},
        ).scalar_one()
    assert key == (
        f"tenants/{packaged['tenant']}/requests/{packaged['rid']}/{packaged['artifact']}.zip"
    )


def test_generation_is_idempotent(client: TestClient, packaged) -> None:
    assert generate(client, packaged["tenant"], packaged["rid"]) is None


# ---------- Uploads ------------------------------------------------------------------

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def upload(
    client: TestClient,
    rid: uuid.UUID,
    headers: dict[str, str],
    name: str,
    content: bytes,
    mime: str,
) -> Any:
    return client.post(
        f"/v1/cases/{rid}/evidence", headers=headers, files={"file": (name, content, mime)}
    )


def test_valid_upload_is_stored_without_its_filename(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = evaluated
    _, a = provision_user(tenant, ["PRIVACY_ANALYST"])
    analyst = bearer(make_token(a))
    r = upload(
        client, rid, analyst, "../../secret/Priya Sharma court order.pdf", PDF, "application/pdf"
    )
    assert r.status_code == 201
    with migrator_engine.connect() as conn:
        key = conn.execute(
            text("SELECT object_key FROM evidence_artifact WHERE id = :a"), {"a": r.json()["id"]}
        ).scalar_one()
    assert key.endswith(f"{r.json()['id']}.pdf") and "priya" not in key.lower()
    got = client.get(f"/v1/cases/{rid}/evidence/{r.json()['id']}/content", headers=analyst)
    assert got.content == PDF and got.headers["content-type"] == "application/pdf"


@pytest.mark.parametrize(
    "name, content, mime, code",
    [
        ("scan.pdf", PNG, "application/pdf", 415),  # wrong magic bytes
        ("scan.png", PNG, "application/pdf", 415),  # MIME doesn't match extension
        ("scan.exe", b"MZ\x90\x00", "application/octet-stream", 415),
        ("scan.html", b"<html>", "text/html", 415),
        ("scan.pdf.exe", PDF, "application/pdf", 415),
        ("scan", PDF, "application/pdf", 415),  # no extension
        ("scan.png", PNG + b"<script>alert(1)</script>", "image/png", 415),  # polyglot
        ("scan.pdf", b"", "application/pdf", 422),
    ],
)
def test_invalid_uploads_rejected(
    client: TestClient,
    evaluated,
    provision_user,
    make_token,
    name: str,
    content: bytes,
    mime: str,
    code: int,
) -> None:
    tenant, rid = evaluated
    _, a = provision_user(tenant, ["PRIVACY_ANALYST"])
    assert upload(client, rid, bearer(make_token(a)), name, content, mime).status_code == code


def test_oversized_upload_is_413(client: TestClient, evaluated, provision_user, make_token) -> None:
    tenant, rid = evaluated
    _, a = provision_user(tenant, ["PRIVACY_ANALYST"])
    big = PDF + b"0" * (11 * 1024 * 1024)
    assert (
        upload(client, rid, bearer(make_token(a)), "big.pdf", big, "application/pdf").status_code
        == 413
    )


def test_upload_permissions(
    client: TestClient, evaluated, provision_user, make_token, make_tenant
) -> None:
    tenant, rid = evaluated
    _, auditor = provision_user(tenant, ["AUDITOR"])
    _, outsider = provision_user(make_tenant(), ["PRIVACY_ANALYST"])
    assert (
        upload(
            client, rid, bearer(make_token(auditor)), "a.pdf", PDF, "application/pdf"
        ).status_code
        == 403
    )
    assert (
        upload(
            client, rid, bearer(make_token(outsider)), "a.pdf", PDF, "application/pdf"
        ).status_code
        == 404
    )
