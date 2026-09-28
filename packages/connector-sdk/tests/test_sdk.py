"""SDK: untrusted-response handling and wire-model constraints."""

import httpx
import pytest
from idprivacy_connector_sdk import (
    ActionRequest,
    ConnectorError,
    DiscoveryRequest,
    HttpConnector,
    Identifier,
    IdentifierType,
    Match,
    idempotency_key,
)
from pydantic import ValidationError

IDENT = [Identifier(type=IdentifierType.EMAIL, value="a@example.in")]
FP = "a" * 64


def _connector(handler) -> HttpConnector:  # type: ignore[no-untyped-def]
    return HttpConnector(
        "http://c", "tok", client=httpx.Client(transport=httpx.MockTransport(handler))
    )


def _match(**overrides) -> dict:  # type: ignore[no-untyped-def]
    body = {
        "source_record_ref": "crm:1",
        "record_type": "crm.contact",
        "data_categories": ["contact"],
        "matched_on": ["EMAIL"],
        "content_fingerprint": FP,
        "attributes": {},
    }
    return {**body, **overrides}


@pytest.mark.parametrize(
    "attrs",
    [
        {"note": "reach me at priya@example.in"},
        {"contact": "+91 98765 43210"},
    ],
)
def test_attributes_that_look_like_personal_data_are_rejected(attrs: dict) -> None:
    with pytest.raises(ValidationError, match="personal data"):
        Match.model_validate(_match(attributes=attrs))


@pytest.mark.parametrize(
    "override",
    [
        {"source_record_ref": "../../etc/passwd"},
        {"record_type": "Crm Contact"},
        {"content_fingerprint": "nothex"},
        {"attributes": {f"k{i}": i for i in range(21)}},
        {"attributes": {"k": "x" * 65}},
        {"attributes": {"k": {"nested": 1}}},
        {"body": "full record content"},
    ],
)
def test_match_constraints(override: dict) -> None:
    with pytest.raises(ValidationError):
        Match.model_validate(_match(**override))


@pytest.mark.parametrize(
    "status, retryable",
    [(503, True), (429, True), (504, True), (500, False), (400, False), (401, False)],
)
def test_http_errors_map_to_retryability(status: int, retryable: bool) -> None:
    c = _connector(lambda _req: httpx.Response(status))
    with pytest.raises(ConnectorError) as exc:
        c.discover(DiscoveryRequest(identifiers=IDENT))
    assert exc.value.retryable is retryable


def test_timeout_is_retryable() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    with pytest.raises(ConnectorError) as exc:
        _connector(boom).discover(DiscoveryRequest(identifiers=IDENT))
    assert exc.value.retryable and exc.value.code == "timeout"


def test_oversized_response_is_rejected() -> None:
    c = _connector(lambda _r: httpx.Response(200, content=b"{" + b" " * 300_000 + b"}"))
    with pytest.raises(ConnectorError, match="too large"):
        c.discover(DiscoveryRequest(identifiers=IDENT))


def test_malformed_response_is_rejected() -> None:
    c = _connector(lambda _r: httpx.Response(200, json={"matches": [_match(extra="x")]}))
    with pytest.raises(ConnectorError) as exc:
        c.discover(DiscoveryRequest(identifiers=IDENT))
    assert exc.value.code == "invalid_response" and not exc.value.retryable


def test_redirects_are_not_followed() -> None:
    c = _connector(lambda _r: httpx.Response(302, headers={"location": "http://evil/"}))
    with pytest.raises(ConnectorError):
        c.discover(DiscoveryRequest(identifiers=IDENT))


def test_action_result_must_echo_the_request() -> None:
    key = idempotency_key("t", "task", "DELETE", "d")
    wrong = {
        "idempotency_key": key,
        "receipt_id": "rcpt_12345678",
        "action": "DELETE",
        "source_record_ref": "crm:other",
        "outcome": "APPLIED",
        "applied_at": "2026-01-01T00:00:00Z",
        "replayed": False,
    }
    c = _connector(lambda _r: httpx.Response(200, json=wrong))
    with pytest.raises(ConnectorError, match="does not match"):
        c.execute_action(
            ActionRequest(idempotency_key=key, action="DELETE", source_record_ref="crm:1")
        )


def test_idempotency_key_is_deterministic() -> None:
    assert idempotency_key("a", 1) == idempotency_key("a", 1) != idempotency_key("a", 2)
    assert len(idempotency_key("x")) == 64
