"""The connector interface (ADR-0006) and the HTTP adapter for the http_v1 wire protocol.

http_v1 (JSON over HTTPS, bearer token):
  GET  {base}/health                   -> ConnectionStatus
  POST {base}/discover                 DiscoveryRequest -> DiscoveryPage
  POST {base}/actions                  ActionRequest    -> ActionResult (idempotent by key)
  POST {base}/verify                   VerifyRequest    -> VerifyResult
  POST {base}/evidence                 EvidenceRequest  -> EvidenceBundle
  POST {base}/export                   ExportRequest    -> ExportBundle (Right to Access)
"""

import hashlib
from typing import Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from idprivacy_connector_sdk.models import (
    MAX_EXPORT_RESPONSE_BYTES,
    ActionRequest,
    ActionResult,
    ConnectionStatus,
    DiscoveryPage,
    DiscoveryRequest,
    EvidenceBundle,
    EvidenceRequest,
    ExportBundle,
    ExportRequest,
    VerifyRequest,
    VerifyResult,
)

MAX_RESPONSE_BYTES = 256 * 1024
_T = TypeVar("_T", bound=BaseModel)


class ConnectorError(Exception):
    """A connector call failed. ``retryable`` says whether the same call may be retried."""

    def __init__(self, message: str, *, retryable: bool, code: str) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.code = code


class Connector(Protocol):
    def test_connection(self) -> ConnectionStatus: ...

    def discover(self, request: DiscoveryRequest) -> DiscoveryPage: ...

    def execute_action(self, request: ActionRequest) -> ActionResult:
        """Must be idempotent: the same key returns the original result, no second effect."""

    def verify_action(self, request: VerifyRequest) -> VerifyResult: ...

    def get_evidence(self, request: EvidenceRequest) -> EvidenceBundle: ...

    def export_records(self, request: ExportRequest) -> ExportBundle:
        """Return content only for the requested records the system holds; omit the rest."""


def idempotency_key(*parts: object) -> str:
    """Deterministic key for a destructive action, e.g. (tenant, task, action, decision)."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


class HttpConnector:
    """Client for connectors that speak http_v1. Responses are size-limited and validated."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        client: httpx.Client | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    def _call(
        self,
        method: str,
        path: str,
        body: BaseModel | None,
        model: type[_T],
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> _T:
        try:
            headers = dict(self._headers)
            if body is not None:
                headers["Content-Type"] = "application/json"
            response = self._client.request(
                method,
                f"{self._base}{path}",
                headers=headers,
                content=body.model_dump_json() if body is not None else None,
            )
        except httpx.TimeoutException as exc:
            # The call may or may not have been applied: retry with the same key.
            raise ConnectorError("connector timed out", retryable=True, code="timeout") from exc
        except httpx.TransportError as exc:
            raise ConnectorError(
                "connector unreachable", retryable=True, code="unreachable"
            ) from exc
        if len(response.content) > max_bytes:
            raise ConnectorError(
                "connector response too large", retryable=False, code="response_too_large"
            )
        if response.status_code in (429, 502, 503, 504):
            raise ConnectorError(
                f"connector returned {response.status_code}",
                retryable=True,
                code=f"http_{response.status_code}",
            )
        if response.status_code >= 400:
            raise ConnectorError(
                f"connector returned {response.status_code}",
                retryable=False,
                code=f"http_{response.status_code}",
            )
        try:
            return model.model_validate_json(response.content)
        except ValidationError as exc:
            raise ConnectorError(
                "connector response failed validation", retryable=False, code="invalid_response"
            ) from exc

    def test_connection(self) -> ConnectionStatus:
        return self._call("GET", "/health", None, ConnectionStatus)

    def discover(self, request: DiscoveryRequest) -> DiscoveryPage:
        return self._call("POST", "/discover", request, DiscoveryPage)

    def execute_action(self, request: ActionRequest) -> ActionResult:
        result = self._call("POST", "/actions", request, ActionResult)
        if (result.idempotency_key, result.source_record_ref, result.action) != (
            request.idempotency_key,
            request.source_record_ref,
            request.action,
        ):
            raise ConnectorError(
                "action result does not match the request",
                retryable=False,
                code="mismatched_result",
            )
        return result

    def verify_action(self, request: VerifyRequest) -> VerifyResult:
        return self._call("POST", "/verify", request, VerifyResult)

    def get_evidence(self, request: EvidenceRequest) -> EvidenceBundle:
        return self._call("POST", "/evidence", request, EvidenceBundle)

    def export_records(self, request: ExportRequest) -> ExportBundle:
        bundle = self._call(
            "POST", "/export", request, ExportBundle, max_bytes=MAX_EXPORT_RESPONSE_BYTES
        )
        requested = set(request.source_record_refs)
        if any(r.source_record_ref not in requested for r in bundle.records):
            raise ConnectorError(
                "connector exported records that weren't requested",
                retryable=False,
                code="unrequested_records",
            )
        return bundle
