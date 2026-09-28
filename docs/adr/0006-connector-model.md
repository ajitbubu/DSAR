# ADR-0006: Connector SDK and idempotent execution

- Status: Proposed. **Connector hosting model for on-prem systems is open decision D-11. Secret backend D-5.**
- Date: 2026-09-25

## Decision

### Interface (`packages/connector-sdk`)
```python
class Connector(Protocol):
    descriptor: ConnectorDescriptor  # id, version, supported actions, record types

    async def test_connection(self, ctx: ConnectorContext) -> ConnectionStatus: ...
    async def discover(self, ctx, req: DiscoveryRequest) -> DiscoveryPage: ...  # paginated
    async def execute_action(
        self, ctx, req: ActionRequest
    ) -> ActionResult: ...  # req.idempotency_key required
    async def verify_action(self, ctx, req: VerifyRequest) -> VerifyResult: ...
    async def get_evidence(self, ctx, req: EvidenceRequest) -> EvidenceBundle: ...
```
- All request and response models are Pydantic with `extra="forbid"` and size limits. Connector output is treated as **untrusted**.
- `DiscoveryRequest` carries canonical identifiers. `DataMatch` returns an opaque `source_record_ref`, `record_type`, `data_categories`, a content fingerprint and **non-PII** attributes used by retention rules (e.g. `has_open_invoice`, `created_at`). No record bodies.
- Actions: `DELETE`, `ANONYMIZE`, `RESTRICT`. `RETAIN` produces no connector call (task `SKIPPED` with reason).

### Idempotency
- `idempotency_key = hex(SHA-256(tenant_id | fulfilment_task_id | action | retention_decision_id))`. It's deterministic and stored with a UNIQUE constraint on `fulfilment_task`.
- The orchestrator (1) commits the task as `DISPATCHED` with `attempt_count+1`, (2) inserts a `connector_execution` row, (3) calls `execute_action`, and (4) records the outcome.
- **Connector contract:** the same key returns the original result with no second side effect. It must be honoured for at least the retention window the connector declares.
- Retries: exponential backoff with jitter on `FAILED_RETRYABLE`, max attempts from config, then `FAILED_FINAL`. If the outcome is unknown (timeout), the retry uses the **same key**, which is safe by contract.
- A **conformance test kit** (`connector_sdk.testing`) every connector must pass covers duplicate-key replay, concurrent same-key calls, pagination, and malformed input rejection.

### Verification
`verify_action` confirms a specific action. The platform **also** runs an independent `discover` rescan and reconciles. A connector's claim alone doesn't close a task.

## Implementation notes (M3)
- The interface is **synchronous** (`Connector` Protocol in `packages/connector-sdk`). Workers are sync Celery processes, and a thread-per-call model is enough at DSAR volumes.
- The wire protocol is `http_v1` (JSON over HTTPS, bearer token): `/health`, `/discover`, `/actions`, `/verify`, `/evidence`. `HttpConnector` enforces a 256 KB response cap, strict model validation, no redirects, and a retryable/non-retryable error mapping (timeouts and 429/502/503/504 are retryable).
- Match attributes must be non-personal. Values that look like emails or phone numbers are rejected by the SDK model.
- The conformance kit (`idprivacy_connector_sdk.testing`) runs read-only checks first, then destructive ones: pagination completeness, stable fingerprints, duplicate-key replay, 8-way concurrent same-key calls, `ALREADY_ABSENT` on re-delete, evidence round-trip, malformed-input rejection, and authentication. A deliberately broken connector test proves the kit catches failures.
- Discovery calls connectors **outside** DB transactions, then persists matches with `ON CONFLICT DO NOTHING`, so retries never duplicate. Only identifiers whose assurance the pinned pack allows (`VERIFIED` in DPDP 1.0.0) are sent.

## Implementation notes (M6)
- Tasks are planned in the approval transaction. The key is `sha256(tenant | task | action | decision)`. `RETAIN` becomes `SKIPPED` with the exception code as its reason and no connector call.
- Dispatch locks the task (`FOR UPDATE SKIP LOCKED`), re-checks legal holds (a hold placed after approval → `SKIPPED: LEGAL_HOLD`), commits `DISPATCHED` with the incremented attempt, then calls the connector **outside** any transaction. A crash leaves the task `DISPATCHED`, and the next run reuses the same key.
- Every completed call is recorded append-only in `connector_execution`. The evidence insert is `ON CONFLICT DO NOTHING`, because concurrent dispatchers may both capture it.
- `FAILED_FINAL` is terminal: after 5 attempts, or a non-retryable error. The case then moves to verification, where the independent rescan (M7) finds the record still present and moves to `RECONCILIATION_REQUIRED`, reopening fulfilment. A failed deletion can't close as done.

## Consequences
+ Destructive calls are safe under retries, worker crashes and duplicate deliveries.
− Every real connector must implement key storage on its side, or wrap a target system that supports idempotency natively.
