# ADR-0005: Workflow model — policy-defined state machine + Celery + transactional outbox

- Status: Proposed
- Date: 2026-09-25

## Context
Regulation rules must not be hard-coded in handlers. Cases are long-running (days to weeks), involve humans (review, approval), and trigger async external calls that must not duplicate.

## Decision
1. **Workflow definitions live in the policy pack** (`packages/policy-packs/dpdp/1.0.0/workflows/erasure.yaml`): states, transitions (`event → from → to`), required permission per event, guard names, and which async steps run on entry. Placeholder rights get a minimal `SUBMITTED → PENDING_MANUAL_HANDLING` workflow.
2. **A generic state-machine engine** in `domain/cases` executes definitions. Guards are named Python functions in a registry (e.g. `all_tasks_terminal`, `approval_valid_for_version`). The pack references them by name, so packs stay declarative data, not code.
3. Transitions use **optimistic locking** (`privacy_request.version`) and write an `AuditEvent` + an **outbox row** in the same transaction.
4. An outbox relay publishes outbox rows to Celery. Tasks are **idempotent** and keyed by outbox id. Celery uses `acks_late=True`, and tasks re-check case state before acting (at-least-once delivery, exactly-once effect).
5. Each case pins `policy_pack_id@version` at jurisdiction decision. In-flight cases never switch pack versions.
6. SLA clocks: `due_at` is computed from `SLA_POLICY` when the clock-start event fires. A periodic Celery beat task flags breaches (values: D-9).

## Implementation notes (M2)
- Intake transitions (submit → verify → hand-off) apply to every regulation and live in `domain/cases/lifecycle.py`. Everything after `JURISDICTION_DETERMINED` comes from the pinned pack's workflow and runs through `domain/policy/workflow.fire`.
- Guards named by a pack but not yet implemented fail closed, so their transition is refused.
- The pack model (`domain/policy/model.py`) is the schema. `packages/policy-packs/schema/policy-pack.schema.json` is generated from it for pack authors.
- Pack integrity: the manifest pins each hash, publishing refuses changed content under an existing version, a DB trigger enforces immutability, and the registry re-hashes on load.
- Verification parameters (OTP TTL, attempts) stay in platform settings, because the OTP is issued before the pack is known. Each pack declares which verification methods it accepts per right, and the jurisdiction step enforces that.

## Consequences
+ Adding GDPR later = new pack + possibly new guard functions. No handler changes.
+ The outbox removes dual-write bugs between DB and broker.
− Celery isn't a durable workflow engine. Long waits are modelled as persisted states, not sleeping tasks. **Revisit trigger:** if we need timers or compensations beyond this, evaluate Temporal.
