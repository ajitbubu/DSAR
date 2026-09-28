"""Right to Access, milestone A2: disclosure review and approval (docs/milestones-access.md)."""

import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from idprivacy.domain.disclosure import service as disclosure
from idprivacy.platform.db import TenantContext, tenant_session
from tests.conftest import bearer
from tests.test_access_a1 import V11
from tests.test_approvals import decide
from tests.test_retention import status_of, transition

# Content only a connector export can produce (identifiers are stored encrypted anyway).
EXPORTED_VALUES = ("Pune", "Complaint letter", "Priya Sharma")
PURPOSES = {
    "purposes": ["Customer support"],
    "recipients": [{"name": "Acme Mail Ltd", "kind": "PROCESSOR"}],
}


def export(
    client: TestClient, ctx: dict[str, Any], factory: Any = None
) -> disclosure.ExportOutcome:
    r = client.post(f"/v1/cases/{ctx['rid']}/disclosure/exports", headers=ctx["analyst"])
    assert r.status_code == 202, r.text
    state = client.app.state  # type: ignore[attr-defined]
    return disclosure.run_export(
        state.app_engine,
        tenant_id=ctx["tenant"],
        export_id=uuid.UUID(r.json()["id"]),
        factory=factory or ctx["factory"],
        cipher=state.cipher,
        store=state.services.blob_store,
    )


def register_all(client: TestClient, ctx: dict[str, Any]) -> None:
    for cid in ("mock-crm", "mock-docs"):
        r = client.post(f"/v1/processing-register/{cid}", json=PURPOSES, headers=ctx["admin"])
        assert r.status_code == 200, r.text


def view(client: TestClient, ctx: dict[str, Any], who: str = "analyst") -> Any:
    return client.get(f"/v1/cases/{ctx['rid']}/disclosure", headers=ctx[who])


def exclude(client: TestClient, ctx: dict[str, Any], **body: Any) -> Any:
    return client.post(
        f"/v1/cases/{ctx['rid']}/disclosure/exclusions", json=body, headers=ctx["analyst"]
    )


def record(v: dict[str, Any], record_type: str) -> dict[str, Any]:
    return next(r for r in v["records"] if r["record_type"] == record_type)


def submit(client: TestClient, ctx: dict[str, Any], engine: Engine) -> Any:
    return transition(client, ctx["rid"], "SUBMIT_FOR_APPROVAL", ctx["analyst"], engine)


def approval_hash(client: TestClient, ctx: dict[str, Any]) -> str:
    return client.get(f"/v1/cases/{ctx['rid']}/retention", headers=ctx["approver"]).json()[
        "decision_set_sha256"
    ]


# ---------- Export ----------------------------------------------------------------------


def test_export_is_encrypted_and_only_hashes_reach_the_db(
    client: TestClient, review, migrator_engine: Engine
) -> None:
    assert export(client, review).status == "READY"
    store = client.app.state.services.blob_store  # type: ignore[attr-defined]
    blobs = [data for key, (data, _) in store.objects.items() if str(review["rid"]) in key]
    assert len(blobs) == 1
    assert not any(v.encode() in blobs[0] for v in EXPORTED_VALUES)
    with migrator_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT status, record_count, content_sha256 FROM disclosure_export "
                "WHERE request_id = :r"
            ),
            {"r": review["rid"]},
        ).one()
    assert row.status == "READY" and row.record_count == 3 and len(row.content_sha256) == 64

    v = view(client, review).json()
    assert {r["record_type"] for r in v["records"]} == {"crm.contact", "crm.invoice", "docs.file"}
    assert any(f["value"] == "Pune" for f in record(v, "crm.contact")["fields"])


def test_export_needs_an_access_case_under_review(
    client: TestClient, review, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    rid = review["rid"]
    assert submit(client, review, migrator_engine).status_code == 409  # nothing exported yet
    transition(client, rid, "BEGIN_REVIEW", review["analyst"], migrator_engine)
    erasure_tenant, erasure_rid = evaluated
    _, sub = provision_user(erasure_tenant, ["PRIVACY_ANALYST"])
    h = bearer(make_token(sub))
    transition(client, erasure_rid, "BEGIN_REVIEW", h, migrator_engine)
    r = client.post(f"/v1/cases/{erasure_rid}/disclosure/exports", headers=h)
    assert r.status_code == 409
    assert client.get(f"/v1/cases/{erasure_rid}/disclosure", headers=h).status_code == 404


def test_records_gone_since_discovery_are_listed_as_missing(client: TestClient, review) -> None:
    class DropsTheFile:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def export_records(self, request: Any) -> Any:
            bundle = self.inner.export_records(request)
            kept = [r for r in bundle.records if r.record_type != "docs.file"]
            return bundle.model_copy(update={"records": kept})

    assert (
        export(client, review, lambda cfg: DropsTheFile(review["factory"](cfg))).status == "READY"
    )
    v = view(client, review).json()
    assert v["export"]["missing_count"] == 1 and len(v["missing"]) == 1
    assert {r["record_type"] for r in v["records"]} == {"crm.contact", "crm.invoice"}


def test_a_connector_failure_fails_the_round_and_a_retry_completes_it(
    client: TestClient, review, mock_connectors: TestClient
) -> None:
    mock_connectors.post(
        "/__test__/faults", json={"account": "acme", "system": "docs", "fail_next": 1}
    )
    first = export(client, review)
    assert (first.status, first.retryable) == ("FAILED", True)
    state = client.app.state  # type: ignore[attr-defined]
    latest = view(client, review).json()["export"]
    assert latest["status"] == "FAILED"
    again = disclosure.run_export(  # what the worker's retry does
        state.app_engine,
        tenant_id=review["tenant"],
        export_id=uuid.UUID(latest["id"]),
        factory=review["factory"],
        cipher=state.cipher,
        store=state.services.blob_store,
    )
    assert again.status == "READY"


# ---------- Viewing ---------------------------------------------------------------------


def test_view_is_audited_uncached_and_limited_to_reviewers_and_approvers(
    client: TestClient, review, make_tenant, provision_user, make_token, migrator_engine: Engine
) -> None:
    export(client, review)
    r = view(client, review)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert view(client, review, "approver").status_code == 200
    assert view(client, review, "auditor").status_code == 403
    assert view(client, review, "admin").status_code == 403
    other = make_tenant(packs=V11)
    _, sub = provision_user(other, ["PRIVACY_ANALYST", "APPROVER"])
    assert (
        client.get(
            f"/v1/cases/{review['rid']}/disclosure", headers=bearer(make_token(sub))
        ).status_code
        == 404
    )
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text(
                "SELECT count(*) FROM audit_event WHERE object_id = :r "
                "AND action = 'disclosure.viewed'"
            ),
            {"r": review["rid"]},
        ).scalar_one()
    assert n == 2


def test_view_before_jurisdiction_is_empty_not_an_error(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    from tests.test_discovery import _verified_with
    from tests.test_public_intake import form

    tenant = make_tenant(packs=V11)
    rid = _verified_with(client, tenant, form("", rights=["ACCESS"]))
    _, sub = provision_user(tenant, ["PRIVACY_ANALYST"])
    r = client.get(f"/v1/cases/{rid}/disclosure", headers=bearer(make_token(sub)))
    assert r.status_code == 200
    assert r.json()["export"] is None and r.json()["reason_codes"] == []


# ---------- Exclusions ------------------------------------------------------------------


def test_exclusions_need_a_pack_reason_and_a_real_record_or_field(
    client: TestClient, review
) -> None:
    export(client, review)
    v = view(client, review).json()
    eid, contact = v["export"]["id"], record(v, "crm.contact")
    base = {"export_id": eid, "data_match_id": contact["match_id"]}
    assert exclude(client, review, **base, action="EXCLUDE").status_code == 422
    assert (
        exclude(client, review, **base, action="EXCLUDE", reason_code="NOT_A_CODE").status_code
        == 422
    )
    assert (
        exclude(
            client,
            review,
            **base,
            field_name="no_such_field",
            action="EXCLUDE",
            reason_code="THIRD_PARTY_DATA",
        ).status_code
        == 422
    )
    assert (
        exclude(
            client,
            review,
            export_id=eid,
            data_match_id=str(uuid.uuid4()),
            action="EXCLUDE",
            reason_code="THIRD_PARTY_DATA",
        ).status_code
        == 422
    )
    assert (
        exclude(
            client,
            review,
            **{**base, "export_id": str(uuid.uuid4())},
            action="EXCLUDE",
            reason_code="THIRD_PARTY_DATA",
        ).status_code
        == 409
    )
    assert (
        exclude(
            client, review, **base, action="INCLUDE", reason_code="THIRD_PARTY_DATA"
        ).status_code
        == 422
    )

    original = v["disclosure_set_sha256"]
    r = exclude(
        client, review, **base, field_name="city", action="EXCLUDE", reason_code="THIRD_PARTY_DATA"
    )
    assert r.status_code == 200 and r.json()["changed"] is True
    changed = r.json()["disclosure_set_sha256"]
    assert changed != original
    again = exclude(
        client, review, **base, field_name="city", action="EXCLUDE", reason_code="THIRD_PARTY_DATA"
    )
    assert again.json() == {"changed": False, "disclosure_set_sha256": changed}
    city = next(
        f
        for f in record(view(client, review).json(), "crm.contact")["fields"]
        if f["name"] == "city"
    )
    assert city["excluded"] and city["reason_code"] == "THIRD_PARTY_DATA"
    back = exclude(client, review, **base, field_name="city", action="INCLUDE")
    assert back.json() == {"changed": True, "disclosure_set_sha256": original}


def test_a_new_export_round_starts_with_no_exclusions(client: TestClient, review) -> None:
    export(client, review)
    v = view(client, review).json()
    exclude(
        client,
        review,
        export_id=v["export"]["id"],
        data_match_id=record(v, "docs.file")["match_id"],
        action="EXCLUDE",
        reason_code="THIRD_PARTY_DATA",
    )
    export(client, review)
    v2 = view(client, review).json()
    assert v2["export"]["round"] == 2
    assert not any(r["excluded"] for r in v2["records"])


def test_exclusions_are_append_only(client: TestClient, review, app_engine: Engine) -> None:
    export(client, review)
    v = view(client, review).json()
    exclude(
        client,
        review,
        export_id=v["export"]["id"],
        data_match_id=record(v, "docs.file")["match_id"],
        action="EXCLUDE",
        reason_code="THIRD_PARTY_DATA",
    )
    for sql in (
        "UPDATE disclosure_exclusion SET reason_code = 'LEGAL_HOLD'",
        "DELETE FROM disclosure_exclusion",
    ):
        with (
            pytest.raises(DBAPIError),
            tenant_session(app_engine, TenantContext(review["tenant"])) as s,
        ):
            s.execute(text(sql))


# ---------- Submission and approval ---------------------------------------------------


def test_submit_needs_a_ready_export_and_register_coverage(
    client: TestClient, review, migrator_engine: Engine
) -> None:
    r = submit(client, review, migrator_engine)
    assert r.status_code == 409 and "export" in r.json()["title"]
    export(client, review)
    r = submit(client, review, migrator_engine)
    assert r.status_code == 409 and "processing register" in r.json()["title"]
    register_all(client, review)
    assert submit(client, review, migrator_engine).status_code == 200
    assert status_of(migrator_engine, review["rid"])[0] == "PENDING_APPROVAL"


def test_approval_is_bound_to_the_disclosure_set(
    client: TestClient, review, migrator_engine: Engine
) -> None:
    export(client, review)
    register_all(client, review)
    submit(client, review, migrator_engine)
    stale = approval_hash(client, review)
    # Anything in the set changing after submission (here, the register) invalidates it.
    changed = {**PURPOSES, "purposes": ["Customer support", "Marketing"]}
    assert (
        client.post(
            "/v1/processing-register/mock-crm", json=changed, headers=review["admin"]
        ).status_code
        == 200
    )
    assert approval_hash(client, review) != stale
    assert decide(client, review["rid"], review["approver"], digest=stale).status_code == 409
    assert (
        decide(client, review["rid"], review["approver"]).status_code == 409
    )  # submission is stale too
    # And the disclosure itself is frozen while awaiting approval.
    assert (
        client.post(
            f"/v1/cases/{review['rid']}/disclosure/exports", headers=review["analyst"]
        ).status_code
        == 409
    )


def test_an_exclusion_author_cannot_approve(
    client: TestClient, review, provision_user, make_token, migrator_engine: Engine
) -> None:
    _, both_sub = provision_user(review["tenant"], ["PRIVACY_ANALYST", "APPROVER"])
    both = bearer(make_token(both_sub))
    export(client, review)
    register_all(client, review)
    v = view(client, review).json()
    r = client.post(
        f"/v1/cases/{review['rid']}/disclosure/exclusions",
        json={
            "export_id": v["export"]["id"],
            "data_match_id": record(v, "docs.file")["match_id"],
            "action": "EXCLUDE",
            "reason_code": "THIRD_PARTY_DATA",
        },
        headers=both,
    )
    assert r.status_code == 200
    submit(client, review, migrator_engine)  # a different analyst submits
    assert decide(client, review["rid"], both).status_code == 403
    assert decide(client, review["rid"], review["approver"]).status_code == 201


def test_an_approved_access_case_builds_a_report_not_erasure_tasks(
    client: TestClient, review, migrator_engine: Engine
) -> None:
    export(client, review)
    register_all(client, review)
    submit(client, review, migrator_engine)
    assert decide(client, review["rid"], review["approver"]).status_code == 201
    assert status_of(migrator_engine, review["rid"])[0] == "FULFILMENT_IN_PROGRESS"
    with migrator_engine.connect() as conn:
        tasks = conn.execute(
            text("SELECT count(*) FROM fulfilment_task WHERE request_id = :r"), {"r": review["rid"]}
        ).scalar_one()
        topics = (
            conn.execute(
                text("SELECT topic FROM outbox WHERE payload->>'request_id' = :r"),
                {"r": str(review["rid"])},
            )
            .scalars()
            .all()
        )
    assert tasks == 0  # no erasure fulfilment for an access case
    assert "case.report_requested" in topics and "case.fulfilment_requested" not in topics


# ---------- Processing register -------------------------------------------------------


def test_register_is_admin_only_validated_and_versioned(
    client: TestClient, review, app_engine: Engine
) -> None:
    url = "/v1/processing-register/mock-crm"
    assert client.post(url, json=PURPOSES, headers=review["analyst"]).status_code == 403
    assert (
        client.post(
            "/v1/processing-register/nope", json=PURPOSES, headers=review["admin"]
        ).status_code
        == 404
    )
    for bad in (
        {**PURPOSES, "purposes": []},
        {**PURPOSES, "purposes": ["ok purpose‮"]},
        {**PURPOSES, "recipients": [{"name": "X Ltd", "kind": "FRIEND"}]},
        {**PURPOSES, "extra": 1},
    ):
        assert client.post(url, json=bad, headers=review["admin"]).status_code == 422, bad
    assert client.post(url, json=PURPOSES, headers=review["admin"]).status_code == 200
    got = {
        e["connector_id"]: e
        for e in client.get("/v1/processing-register", headers=review["analyst"]).json()
    }
    assert got["mock-crm"]["purposes"] == ["Customer support"]
    assert got["mock-docs"]["entry_id"] is None
    with (
        pytest.raises(DBAPIError),
        tenant_session(app_engine, TenantContext(review["tenant"])) as s,
    ):
        s.execute(text("UPDATE processing_register_entry SET purposes = '[]'"))


# ---------- No exported content outside the encrypted blob ----------------------------


def test_exported_values_never_reach_db_rows_audit_or_logs(
    client: TestClient,
    review,
    migrator_engine: Engine,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    export(client, review)
    register_all(client, review)
    v = view(client, review).json()
    exclude(
        client,
        review,
        export_id=v["export"]["id"],
        data_match_id=record(v, "crm.contact")["match_id"],
        field_name="city",
        action="EXCLUDE",
        reason_code="THIRD_PARTY_DATA",
    )
    submit(client, review, migrator_engine)
    decide(client, review["rid"], review["approver"])

    with migrator_engine.connect() as conn:
        # Every table holding tenant data, scoped to this test's tenant.
        tables = (
            conn.execute(
                text(
                    "SELECT table_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
                )
            )
            .scalars()
            .all()
        )
        assert {"audit_event", "outbox", "disclosure_export", "data_match"} <= set(tables)
        dump = "\n".join(
            row
            for t in tables
            for row in conn.execute(
                text(f'SELECT t::text FROM "{t}" t WHERE tenant_id = :t'), {"t": review["tenant"]}
            ).scalars()
        )
    assert str(review["rid"]) in dump
    logs = caplog.text + capsys.readouterr().out
    assert "disclosure" in logs  # the capture is live
    for value in EXPORTED_VALUES:
        assert value not in dump, value
        assert value not in logs, value
    assert json.dumps(v)  # the reviewer did see the content, through the audited view
