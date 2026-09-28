"""Maker-checker approval (M5; threat model T-11)."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from tests.conftest import bearer
from tests.test_retention import override, status_of, transition


def _user(
    provision_user, make_token, tenant: uuid.UUID, *roles: str
) -> tuple[uuid.UUID, dict[str, str]]:
    uid, sub = provision_user(tenant, list(roles))
    return uid, bearer(make_token(sub))


@pytest.fixture
def pending(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> dict[str, Any]:
    """Analyst A reviews, retains the invoice, and submits for approval."""
    tenant, rid = evaluated
    analyst_id, analyst = _user(provision_user, make_token, tenant, "PRIVACY_ANALYST")
    transition(client, rid, "BEGIN_REVIEW", analyst, migrator_engine)
    assert override(client, rid, "crm:invoice:i-5001", analyst, migrator_engine).status_code == 201
    assert (
        transition(client, rid, "SUBMIT_FOR_APPROVAL", analyst, migrator_engine).status_code == 200
    )
    _, approver = _user(provision_user, make_token, tenant, "APPROVER")
    return {
        "tenant": tenant,
        "rid": rid,
        "analyst": analyst,
        "analyst_id": analyst_id,
        "approver": approver,
    }


def snapshot(client: TestClient, rid: uuid.UUID, headers: dict[str, str]) -> tuple[int, str]:
    view = client.get(f"/v1/cases/{rid}/retention", headers=headers).json()
    return view["case_version"], view["decision_set_sha256"]


def decide(
    client: TestClient,
    rid: uuid.UUID,
    headers: dict[str, str],
    *,
    outcome: str = "APPROVED",
    key: str | None = None,
    version: int | None = None,
    digest: str | None = None,
    comment: str | None = None,
) -> Any:
    v, h = snapshot(client, rid, headers)
    body: dict[str, Any] = {
        "outcome": outcome,
        "case_version": version or v,
        "decision_set_sha256": digest or h,
    }
    if comment is not None:
        body["comment"] = comment
    return client.post(
        f"/v1/cases/{rid}/approvals",
        json=body,
        headers={**headers, "Idempotency-Key": key or uuid.uuid4().hex},
    )


def approvals_count(engine: Engine, rid: uuid.UUID) -> int:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM approval WHERE request_id = :r"),  # type: ignore[no-any-return]
            {"r": rid},
        ).scalar_one()


def test_separate_approver_approves(client: TestClient, pending, migrator_engine: Engine) -> None:
    rid, approver = pending["rid"], pending["approver"]
    r = decide(client, rid, approver)
    assert r.status_code == 201 and r.json()["outcome"] == "APPROVED"
    assert r.json()["submitted_by"] == str(pending["analyst_id"])
    assert status_of(migrator_engine, rid)[0] == "APPROVED"
    history = client.get(f"/v1/cases/{rid}/approvals", headers=pending["analyst"]).json()
    assert [h["outcome"] for h in history] == ["APPROVED"]
    with migrator_engine.connect() as conn:
        actions = (
            conn.execute(
                text("SELECT action FROM audit_event WHERE object_id = :r ORDER BY seq"), {"r": rid}
            )
            .scalars()
            .all()
        )
    assert "approval.submitted" in actions and "approval.approved" in actions


def test_replayed_key_returns_identical_response_once(
    client: TestClient, pending, migrator_engine: Engine
) -> None:
    rid, approver = pending["rid"], pending["approver"]
    version, digest = snapshot(client, rid, approver)
    key = uuid.uuid4().hex
    first = decide(client, rid, approver, key=key, version=version, digest=digest)
    again = decide(client, rid, approver, key=key, version=version, digest=digest)
    assert first.status_code == again.status_code == 201
    assert first.json() == again.json()
    assert approvals_count(migrator_engine, rid) == 1
    assert status_of(migrator_engine, rid)[0] == "APPROVED"
    clash = decide(
        client,
        rid,
        approver,
        key=key,
        outcome="REJECTED",
        comment="Changed my mind about this one.",
    )
    assert clash.status_code == 409


def test_submitter_cannot_approve_even_with_approver_role(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = evaluated
    _, both = _user(provision_user, make_token, tenant, "PRIVACY_ANALYST", "APPROVER")
    transition(client, rid, "BEGIN_REVIEW", both, migrator_engine)
    override(client, rid, "crm:invoice:i-5001", both, migrator_engine)
    transition(client, rid, "SUBMIT_FOR_APPROVAL", both, migrator_engine)
    r = decide(client, rid, both)
    assert r.status_code == 403 and "submitted" in r.json()["title"]
    assert approvals_count(migrator_engine, rid) == 0


def test_override_author_cannot_approve(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = evaluated
    _, author = _user(provision_user, make_token, tenant, "PRIVACY_ANALYST", "APPROVER")
    _, submitter = _user(provision_user, make_token, tenant, "PRIVACY_ANALYST")
    transition(client, rid, "BEGIN_REVIEW", submitter, migrator_engine)
    override(client, rid, "crm:invoice:i-5001", author, migrator_engine)
    transition(client, rid, "SUBMIT_FOR_APPROVAL", submitter, migrator_engine)
    r = decide(client, rid, author)
    assert r.status_code == 403 and "changed decisions" in r.json()["title"]


def test_db_rejects_maker_as_checker(pending, migrator_engine: Engine) -> None:
    with pytest.raises(IntegrityError, match="maker_checker"):
        with migrator_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO approval (id, tenant_id, request_id, submission_id, case_version, "
                    "decision_set_sha256, submitted_by, approved_by, outcome, idempotency_key, "
                    "response) SELECT gen_random_uuid(), tenant_id, request_id, id, case_version, "
                    "decision_set_sha256, submitted_by, submitted_by, 'APPROVED', "
                    "'k-0123456789abcd', "
                    "'{}' FROM approval_submission WHERE request_id = :r"
                ),
                {"r": pending["rid"]},
            )


def test_stale_version_or_hash_is_409(client: TestClient, pending) -> None:
    rid, approver = pending["rid"], pending["approver"]
    version, digest = snapshot(client, rid, approver)
    assert decide(client, rid, approver, version=version - 1).status_code == 409
    assert decide(client, rid, approver, digest="0" * 64).status_code == 409


def test_decisions_changing_after_submission_invalidate_approval(
    client: TestClient, pending
) -> None:
    """A legal hold changes decisions without bumping the version: the hash catches it."""
    rid, analyst, approver = pending["rid"], pending["analyst"], pending["approver"]
    version, digest = snapshot(client, rid, approver)
    held = client.post(
        "/v1/legal-holds",
        json={
            "scope": "CASE",
            "case_id": str(rid),
            "matter_ref": "LIT-9",
            "reason": "Litigation hold arrived late.",
        },
        headers=analyst,
    )
    assert held.status_code == 201 and held.json()["decisions_changed"] >= 1
    r = decide(client, rid, approver, version=version, digest=digest)
    assert r.status_code == 409 and "decisions changed" in r.json()["title"]


def test_rejection_needs_a_comment_and_returns_for_rework(
    client: TestClient, pending, migrator_engine: Engine
) -> None:
    rid, analyst, approver = pending["rid"], pending["analyst"], pending["approver"]
    assert decide(client, rid, approver, outcome="REJECTED").status_code == 422
    assert decide(client, rid, approver, outcome="REJECTED", comment="short").status_code == 422
    r = decide(
        client,
        rid,
        approver,
        outcome="REJECTED",
        comment="Invoice retention basis needs the GST section cited.",
    )
    assert r.status_code == 201
    assert status_of(migrator_engine, rid)[0] == "REJECTED"
    assert (
        transition(client, rid, "REWORK", analyst, migrator_engine).json()["status"]
        == "UNDER_REVIEW"
    )
    history = client.get(f"/v1/cases/{rid}/approvals", headers=analyst).json()
    assert history[-1]["outcome"] == "REJECTED" and "GST" in history[-1]["comment"]


def test_approve_cannot_bypass_maker_checker_via_transitions(
    client: TestClient, pending, migrator_engine: Engine
) -> None:
    rid, approver = pending["rid"], pending["approver"]
    for event in ("APPROVE", "REJECT"):
        r = transition(client, rid, event, approver, migrator_engine)
        assert r.status_code == 409 and "approvals endpoint" in r.json()["title"]
    assert status_of(migrator_engine, rid)[0] == "PENDING_APPROVAL"


def test_second_decision_after_approval_is_409(
    client: TestClient, pending, provision_user, make_token
) -> None:
    rid = pending["rid"]
    assert decide(client, rid, pending["approver"]).status_code == 201
    _, other = _user(provision_user, make_token, pending["tenant"], "APPROVER")
    assert decide(client, rid, other).status_code == 409


def test_concurrent_approvers_only_one_wins(
    client: TestClient, pending, provision_user, make_token, migrator_engine: Engine
) -> None:
    rid = pending["rid"]
    approvers = [
        _user(provision_user, make_token, pending["tenant"], "APPROVER")[1] for _ in range(4)
    ]
    version, digest = snapshot(client, rid, approvers[0])
    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(
            pool.map(
                lambda h: decide(client, rid, h, version=version, digest=digest).status_code,
                approvers,
            )
        )
    assert sorted(codes) == [201, 409, 409, 409]
    assert approvals_count(migrator_engine, rid) == 1


@pytest.mark.parametrize("key", ["", "short", "has spaces in it ok?", "x" * 129])
def test_idempotency_key_is_required_and_validated(client: TestClient, pending, key: str) -> None:
    rid, approver = pending["rid"], pending["approver"]
    version, digest = snapshot(client, rid, approver)
    headers = {**approver, "Idempotency-Key": key} if key else approver
    r = client.post(
        f"/v1/cases/{rid}/approvals",
        json={"outcome": "APPROVED", "case_version": version, "decision_set_sha256": digest},
        headers=headers,
    )
    assert r.status_code == 422


def test_authorisation_matrix(
    client: TestClient, pending, provision_user, make_token, make_tenant
) -> None:
    rid, tenant = pending["rid"], pending["tenant"]
    for role in ("PRIVACY_ANALYST", "AUDITOR", "TENANT_ADMIN"):
        _, h = _user(provision_user, make_token, tenant, role)
        body = {"outcome": "APPROVED", "case_version": 1, "decision_set_sha256": "a" * 64}
        r = client.post(
            f"/v1/cases/{rid}/approvals",
            json=body,
            headers={**h, "Idempotency-Key": uuid.uuid4().hex},
        )
        assert r.status_code == 403, role
        assert client.get("/v1/approvals/queue", headers=h).status_code == 403, role
    _, outsider = _user(provision_user, make_token, make_tenant(), "APPROVER")
    body = {"outcome": "APPROVED", "case_version": 1, "decision_set_sha256": "a" * 64}
    assert (
        client.post(
            f"/v1/cases/{rid}/approvals",
            json=body,
            headers={**outsider, "Idempotency-Key": uuid.uuid4().hex},
        ).status_code
        == 404
    )
    assert all(
        i["id"] != str(rid) for i in client.get("/v1/approvals/queue", headers=outsider).json()
    )
    assert client.post(f"/v1/cases/{rid}/approvals", json=body).status_code == 401


def test_queue_flags_cases_you_submitted(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = evaluated
    _, both = _user(provision_user, make_token, tenant, "PRIVACY_ANALYST", "APPROVER")
    transition(client, rid, "BEGIN_REVIEW", both, migrator_engine)
    override(client, rid, "crm:invoice:i-5001", both, migrator_engine)
    transition(client, rid, "SUBMIT_FOR_APPROVAL", both, migrator_engine)
    _, approver = _user(provision_user, make_token, tenant, "APPROVER")
    mine = {
        i["id"]: i["you_submitted"] for i in client.get("/v1/approvals/queue", headers=both).json()
    }
    theirs = {
        i["id"]: i["you_submitted"]
        for i in client.get("/v1/approvals/queue", headers=approver).json()
    }
    assert mine[str(rid)] is True and theirs[str(rid)] is False
