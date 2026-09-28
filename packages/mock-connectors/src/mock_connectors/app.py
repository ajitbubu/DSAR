"""Mock CRM and document-store systems speaking the connector http_v1 protocol.

Routes: /{account}/{system}/{health|discover|actions|verify|evidence}, where system is
"crm" or "docs". Accounts are independent (a tenant's connector config points at one).

State is in memory and resets on restart. Test-only endpoints (reset, call log, fault
injection) exist only when MOCK_TEST_ENDPOINTS=true.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import UTC, datetime
from importlib import resources
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from idprivacy_connector_sdk.models import (
    Action,
    ActionRequest,
    ActionResult,
    ConnectionStatus,
    ConnectorDescriptor,
    DiscoveryPage,
    DiscoveryRequest,
    EvidenceBundle,
    EvidenceRequest,
    Match,
    VerifyRequest,
    VerifyResult,
)
from pydantic import BaseModel, ConfigDict

System = Literal["crm", "docs"]
DESCRIPTORS = {
    "crm": ConnectorDescriptor(
        connector_id="mock-crm",
        version="1.0.0",
        record_types=["crm.contact", "crm.invoice", "crm.ticket"],
        supported_actions=list(Action),
        idempotency_retention_days=365,
    ),
    "docs": ConnectorDescriptor(
        connector_id="mock-docs",
        version="1.0.0",
        record_types=["docs.file"],
        supported_actions=[Action.DELETE, Action.RESTRICT],
        idempotency_retention_days=365,
    ),
}


def load_seed() -> dict[str, Any]:
    text = resources.files("mock_connectors").joinpath("data/seed.json").read_text()
    return json.loads(text)  # type: ignore[no-any-return]


class Fault(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account: str
    system: System
    fail_next: int = 1
    status: int = 503
    apply_before_failing: bool = False  # simulates a timeout after the effect happened


class _SystemState:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = {r["ref"]: {**copy.deepcopy(r), "state": "PRESENT"} for r in records}
        self.by_key: dict[str, ActionResult] = {}
        self.receipts: dict[str, EvidenceBundle] = {}
        self.lock = threading.Lock()


class MockState:
    def __init__(self, seed: dict[str, Any]) -> None:
        self.seed = seed
        self.reset()

    def reset(self) -> None:
        self.systems = {
            (acct, sys): _SystemState(recs)
            for acct, systems in self.seed["accounts"].items()
            for sys, recs in systems.items()
        }
        self.calls: list[dict[str, Any]] = []
        self.faults: dict[tuple[str, str], Fault] = {}
        self.lock = threading.Lock()

    def system(self, account: str, system: str) -> _SystemState:
        found = self.systems.get((account, system))
        if found is None:
            raise HTTPException(404, "unknown account or system")
        return found


def _fingerprint(record: dict[str, Any]) -> str:
    body = {k: record[k] for k in ("identifiers", "content", "state", "attributes")}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _matches(record: dict[str, Any], wanted: dict[str, set[str]]) -> list[str]:
    hits = []
    for id_type, values in record["identifiers"].items():
        if {v.lower() if id_type == "EMAIL" else v for v in values} & wanted.get(id_type, set()):
            hits.append(id_type)
    return sorted(hits)


def create_app(
    seed: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    test_endpoints: bool | None = None,
) -> FastAPI:
    token = token or os.environ.get("MOCK_CONNECTOR_TOKEN", "")
    if len(token) < 16:
        raise RuntimeError("MOCK_CONNECTOR_TOKEN must be set (16+ chars)")
    if test_endpoints is None:
        test_endpoints = os.environ.get("MOCK_TEST_ENDPOINTS") == "true"
    state = MockState(seed or load_seed())
    app = FastAPI(title="ID-PRIVACY mock connectors", docs_url=None, redoc_url=None)
    app.state.mock = state

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    def authenticate(authorization: Annotated[str, Header()] = "") -> None:
        scheme, _, supplied = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(401, "unauthenticated")

    Auth = Depends(authenticate)

    def record_call(account: str, system: str, op: str, **extra: Any) -> None:
        with state.lock:
            state.calls.append({"account": account, "system": system, "op": op, **extra})

    def maybe_fail(account: str, system: str, apply: Any = None) -> None:
        with state.lock:
            fault = state.faults.get((account, system))
            if fault is None or fault.fail_next <= 0:
                return
            fault.fail_next -= 1
        if fault.apply_before_failing and apply is not None:
            apply()
        raise HTTPException(fault.status, "injected fault")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/{account}/{system}/health", dependencies=[Auth])
    def health(account: str, system: System) -> ConnectionStatus:
        state.system(account, system)
        return ConnectionStatus(ok=True, descriptor=DESCRIPTORS[system])

    @app.post("/{account}/{system}/discover", dependencies=[Auth])
    def discover(account: str, system: System, body: DiscoveryRequest) -> DiscoveryPage:
        sys_state = state.system(account, system)
        record_call(account, system, "discover")
        maybe_fail(account, system)
        wanted: dict[str, set[str]] = {}
        for ident in body.identifiers:
            value = ident.value.lower() if ident.type == "EMAIL" else ident.value
            wanted.setdefault(ident.type.value, set()).add(value)
        with sys_state.lock:
            hits = []
            for ref in sorted(sys_state.records):
                rec = sys_state.records[ref]
                if rec["state"] in ("ABSENT", "ANONYMIZED"):
                    continue
                on = _matches(rec, wanted)
                if on:
                    hits.append(
                        Match(
                            source_record_ref=ref,
                            record_type=rec["record_type"],
                            data_categories=rec["categories"],
                            matched_on=on,
                            content_fingerprint=_fingerprint(rec),
                            attributes={
                                **rec["attributes"],
                                "restricted": rec["state"] == "RESTRICTED",
                            },
                        )
                    )
        try:
            offset = int(base64.urlsafe_b64decode(body.page_token)) if body.page_token else 0
        except ValueError:
            raise HTTPException(422, "invalid page token") from None
        page = hits[offset : offset + body.page_size]
        nxt = offset + body.page_size
        token_out = (
            base64.urlsafe_b64encode(str(nxt).encode()).decode() if nxt < len(hits) else None
        )
        return DiscoveryPage(matches=page, next_page_token=token_out)

    @app.post("/{account}/{system}/actions", dependencies=[Auth])
    def actions(account: str, system: System, body: ActionRequest) -> ActionResult:
        sys_state = state.system(account, system)
        if body.action not in DESCRIPTORS[system].supported_actions:
            raise HTTPException(422, "action not supported")
        with sys_state.lock:
            record_call(
                account,
                system,
                "execute_action",
                key=body.idempotency_key,
                action=body.action.value,
                ref=body.source_record_ref,
            )
            prior = sys_state.by_key.get(body.idempotency_key)
            if prior is not None:
                if (prior.action, prior.source_record_ref) != (body.action, body.source_record_ref):
                    raise HTTPException(409, "idempotency key reused for a different action")
                return prior.model_copy(update={"replayed": True})

            def apply() -> ActionResult:
                rec = sys_state.records.get(body.source_record_ref)
                present = rec is not None and rec["state"] != "ABSENT"
                if present:
                    assert rec is not None
                    if body.action == Action.DELETE:
                        rec["state"] = "ABSENT"
                    elif body.action == Action.ANONYMIZE:
                        rec["state"], rec["identifiers"], rec["content"] = "ANONYMIZED", {}, {}
                    else:
                        rec["state"] = "RESTRICTED"
                    record_call(
                        account,
                        system,
                        "effect",
                        key=body.idempotency_key,
                        action=body.action.value,
                        ref=body.source_record_ref,
                    )
                result = ActionResult(
                    idempotency_key=body.idempotency_key,
                    receipt_id=f"rcpt_{secrets.token_hex(8)}",
                    action=body.action,
                    source_record_ref=body.source_record_ref,
                    outcome="APPLIED" if present else "ALREADY_ABSENT",
                    applied_at=datetime.now(UTC),
                    replayed=False,
                )
                sys_state.by_key[body.idempotency_key] = result
                statement = (
                    f"{DESCRIPTORS[system].connector_id} {result.outcome.lower()} "
                    f"{body.action.value} on {body.source_record_ref}"
                )
                digest = hashlib.sha256(f"{result.model_dump_json()}|{statement}".encode())
                sys_state.receipts[result.receipt_id] = EvidenceBundle(
                    receipt_id=result.receipt_id,
                    idempotency_key=result.idempotency_key,
                    action=result.action,
                    source_record_ref=result.source_record_ref,
                    applied_at=result.applied_at,
                    system_statement=statement,
                    sha256=digest.hexdigest(),
                )
                return result

            maybe_fail(account, system, apply)
            return apply()

    @app.post("/{account}/{system}/verify", dependencies=[Auth])
    def verify(account: str, system: System, body: VerifyRequest) -> VerifyResult:
        sys_state = state.system(account, system)
        record_call(account, system, "verify", ref=body.source_record_ref)
        rec = sys_state.records.get(body.source_record_ref)
        observed = "ABSENT" if rec is None else rec["state"]
        return VerifyResult(source_record_ref=body.source_record_ref, observed=observed)

    @app.post("/{account}/{system}/evidence", dependencies=[Auth])
    def evidence(account: str, system: System, body: EvidenceRequest) -> EvidenceBundle:
        found = state.system(account, system).receipts.get(body.receipt_id)
        if found is None:
            raise HTTPException(404, "unknown receipt")
        return found

    if test_endpoints:

        @app.post("/__test__/reset")
        def reset() -> dict[str, str]:
            state.reset()
            return {"status": "reset"}

        @app.get("/__test__/calls")
        def calls() -> list[dict[str, Any]]:
            with state.lock:
                return list(state.calls)

        @app.post("/__test__/faults")
        def faults(fault: Fault) -> dict[str, str]:
            with state.lock:
                state.faults[(fault.account, fault.system)] = fault
            return {"status": "armed"}

    return app


def app() -> FastAPI:  # uvicorn factory: `uvicorn mock_connectors.app:app --factory`
    return create_app()
