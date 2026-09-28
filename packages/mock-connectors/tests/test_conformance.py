"""Both mock connectors must pass the SDK conformance kit (M3 acceptance)."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from idprivacy_connector_sdk import HttpConnector, Identifier, IdentifierType
from idprivacy_connector_sdk.testing import ConformanceKit, ConformanceTarget

from mock_connectors.app import create_app

TOKEN = "test-mock-connector-token"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(token=TOKEN, test_endpoints=True))


def _target(client: TestClient, system: str, disposable: list[str]) -> ConformanceTarget:
    base = f"http://testserver/acme/{system}"

    def raw_post(path: str, body: Any, authenticated: bool) -> int:
        headers = {"Authorization": f"Bearer {TOKEN}"} if authenticated else {}
        kwargs = {"json": body} if not isinstance(body, str) else {"content": body}
        return client.post(f"/acme/{system}{path}", headers=headers, **kwargs).status_code

    return ConformanceTarget(
        connector=HttpConnector(base, TOKEN, client=client),
        matching=[
            Identifier(type=IdentifierType.EMAIL, value="priya.sharma@example.in"),
            Identifier(type=IdentifierType.PHONE, value="+919876543210"),
            Identifier(type=IdentifierType.EMAIL, value="rahul.verma@example.in"),
        ],
        non_matching=[Identifier(type=IdentifierType.EMAIL, value="nobody@example.in")],
        disposable_refs=disposable,
        raw_post=raw_post,
        namespace=system,
    )


@pytest.mark.parametrize(
    "system, disposable",
    [
        ("crm", ["crm:contact:c-1001", "crm:ticket:t-7001", "crm:contact:c-3003"]),
        ("docs", ["docs:file:d-3001", "docs:file:d-3002", "docs:file:d-4001"]),
    ],
)
def test_mock_connector_passes_conformance_kit(
    client: TestClient, system: str, disposable: list[str]
) -> None:
    assert ConformanceKit(_target(client, system, disposable)).run_all() == {}


def test_accounts_are_isolated(client: TestClient) -> None:
    from idprivacy_connector_sdk import DiscoveryRequest

    ident = [Identifier(type=IdentifierType.EMAIL, value="priya.sharma@example.in")]
    acme = HttpConnector("http://testserver/acme/crm", TOKEN, client=client).discover(
        DiscoveryRequest(identifiers=ident)
    )
    globex = HttpConnector("http://testserver/globex/crm", TOKEN, client=client).discover(
        DiscoveryRequest(identifiers=ident)
    )
    assert {m.source_record_ref for m in acme.matches}.isdisjoint(
        {m.source_record_ref for m in globex.matches}
    )


def test_same_key_different_action_is_a_conflict(client: TestClient) -> None:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    body = {
        "idempotency_key": "b" * 64,
        "action": "DELETE",
        "source_record_ref": "crm:contact:c-3003",
    }
    assert client.post("/acme/crm/actions", json=body, headers=headers).status_code == 200
    clash = {**body, "source_record_ref": "crm:contact:c-1001"}
    assert client.post("/acme/crm/actions", json=clash, headers=headers).status_code == 409


def test_invalid_page_token_is_422(client: TestClient) -> None:
    body = {"identifiers": [{"type": "EMAIL", "value": "x@example.in"}], "page_token": "@@@"}
    r = client.post("/acme/crm/discover", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 422


def test_test_endpoints_are_off_by_default() -> None:
    plain = TestClient(create_app(token=TOKEN, test_endpoints=False))
    assert plain.post("/__test__/reset").status_code in (404, 405)


def test_missing_token_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MOCK_CONNECTOR_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        create_app()
