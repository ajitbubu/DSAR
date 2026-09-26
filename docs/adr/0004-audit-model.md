# ADR-0004: Append-only, tamper-evident audit model

- Status: Proposed. **Audit retention period is open decision D-4.**
- Date: 2026-09-25

## Decision
- One `audit_event` table. Every state transition, retention decision, override, approval, connector call, evidence generation, download, login-derived access to a case and admin change writes one event **in the same DB transaction** as the change it records.
- Fields: `seq` (per-tenant monotonic), `occurred_at`, `actor_type`, `actor_ref` (user id / "data_principal:{request_id}" / "system:{task}"), `action`, `object_type`, `object_id`, `details` (JSON, **redacted, no PII**), `prev_hash`, `hash`.
- `hash = SHA-256(prev_hash || canonical_json(event_without_hash))` per tenant (stdlib `hashlib`, a standard primitive, not custom crypto). Per-tenant append is serialised with a row lock on a `tenant_audit_head` row.
- Enforcement: the app role has only `INSERT, SELECT`. A `BEFORE UPDATE OR DELETE` trigger raises. Supersession rather than update is also used for `retention_decision`, `approval`, `connector_execution` and `verification_result`.
- `GET /audit/verify` (auditor) recomputes the chain and reports the first break.
- Audit events for a case are included, redacted, in its evidence package.

## Consequences
+ Tamper-*evident* inside the DB. A DB superuser could still rewrite the whole chain. Mitigate later with external anchoring or WORM export (D-4).
− Per-tenant serialisation limits audit write throughput per tenant. That's fine at DSAR volumes.

## Alternatives
Separate ledger DB or immudb: deferred. Event sourcing the entire domain: rejected as excess complexity for v1.
