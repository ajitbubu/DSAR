# ID-PRIVACY DPAR/DSAR Automation

A DPDP-first platform for automating Data Principal / Data Subject rights requests. The first release is a complete **Right to Erasure** vertical slice.

- Scope, architecture, threat model and ADRs: [`docs/`](docs/)
- Milestones and acceptance criteria: [`docs/milestones.md`](docs/milestones.md)
- Open security and tenancy decisions: [`docs/open-decisions.md`](docs/open-decisions.md)

**Status:** the first vertical slice (Right to Erasure, milestones M0–M9) is complete and verified end to end. Production readiness depends on the open decisions in [`docs/open-decisions.md`](docs/open-decisions.md). See [`docs/architecture/production-deployment.md`](docs/architecture/production-deployment.md).

## Layout

```
apps/api                 FastAPI + shared domain package `idprivacy` (Alembic migrations here)
apps/worker              Celery workers + outbox relay (`idprivacy_worker`)
apps/web                 Next.js UI + BFF (pages arrive in M1)
packages/connector-sdk   Connector interface, http_v1 wire models, HTTP adapter, conformance kit
packages/mock-connectors Simulated CRM + document store speaking http_v1 (seeded, fault injection)
packages/policy-packs    Versioned regulation packs (DPDP 1.0.0), manifest of pinned hashes, JSON Schema
contracts/openapi.json   Generated API contract; tests fail on drift (`make contracts`)
infra/compose            Docker Compose stack, Postgres role init, Keycloak dev realm, S3 stand-in
```

## Prerequisites

Docker, [uv](https://docs.astral.sh/uv/), pnpm 9, and Node 24 (only needed for local web work). Containers pin Python 3.12 and Node 24, so host versions don't affect them.

## Quick start

```bash
uv sync --all-packages && pnpm install
make up        # full stack, waits until healthy
make smoke     # Keycloak token -> API authz, outbox -> worker, log redaction
make test      # API (needs Postgres + Redis), worker, web
make test-e2e  # Playwright against the running stack
make lint      # ruff, mypy --strict, tsc
make logscan   # fail if seeded identifiers/tokens appear in service logs
make security  # pip-audit, pnpm audit, gitleaks
```

Try the Data Principal flow at http://localhost:3000/r/acme (use `priya.sharma@example.in` to hit seeded mock records), then sign in to the console at http://localhost:3000/ops as `analyst@acme.example.test`. The dev password is in the Keycloak realm fixture. The stack runs the API with `IDP_ENV=test`, so the verify screen shows the mock OTP (development only).

| Service | URL | Notes |
|---|---|---|
| web | http://localhost:3000 | Erasure request form at `/r/acme` or `/r/globex` |
| api | http://localhost:8000/docs | OpenAPI UI only in local/test |
| keycloak | http://localhost:8080 | **Dev-only** stand-in for the staff IdP (decision D-1) |
| object storage | http://localhost:8333 | SeaweedFS S3 gateway, a dev-only stand-in. MinIO images are no longer published. |
| postgres | localhost:5432 | Roles: `idp_migrator` (owner), `idp_app`, `idp_relay` |
| redis | localhost:16379 | Host port 6379 is often already taken |

Every credential in this repo (`.env.example`, the Keycloak realm, `seaweedfs/s3.json`) is a local-development fixture. The app refuses to boot with the mock OTP provider or the local key provider outside `local`/`test`.

## What M0 provides

- **Tenancy:** `tenant_id` on every tenant table, composite FKs, and Postgres RLS enforced for the non-owner `idp_app` role. The tenant is resolved only from the verified token (ADR-0002).
- **Auth:** the API validates OIDC tokens as a resource server (issuer, audience, expiry, asymmetric-algorithm allowlist). Roles come from the platform DB. Every route must declare `Requires(permission)` or `Public()`, and a test enforces it (ADR-0003).
- **Audit:** append-only `audit_event`. UPDATE/DELETE/TRUNCATE are revoked and trigger-blocked. A per-tenant SHA-256 hash chain is checked by `POST /v1/audit/verify` (ADR-0004).
- **Outbox:** a transactional outbox with an identifier-only payload guard. A relay running as the `idp_relay` role feeds Celery (acks-late, JSON only) (ADR-0005).
- **Crypto:** AES-256-GCM envelope encryption and HMAC blind indexes behind a `KeyProvider` interface. The dev provider is local only (decision D-3).
- **Logging:** structured JSON for structlog and stdlib logs, with key- and pattern-based PII redaction.

## What M1 provides

- **Screens 1–3:** the erasure request form, OTP verification, and confirmation/tracking with withdraw. There's no case id, challenge id or token in any browser URL.
- **BFF:** Next.js route handlers enforce CSRF (exact Origin, `Sec-Fetch-Site`, JSON-only, double-submit token). All cookies are `__Host-`, httpOnly, Secure and SameSite=Strict. There's a nonce-based CSP with no `unsafe-inline`.
- **Intake:** allowlist schemas with length limits, no input echoed in 422 responses, 413 above 64 KB (declared or streamed), and rate limits per IP and per contact (against OTP-bombing). Names, identifiers and details are envelope-encrypted, and the contact is looked up by blind index.
- **OTP:** a keyed-HMAC hash, attempts counted under a row lock, a lock after 5 failed attempts, expiry, single use, and resends that don't reset the counter. The mock provider's inspection endpoint exists only in `test`.
- **Tracking session:** an opaque 256-bit token stored hashed and bound to one request, with sliding idle and absolute expiry.

## What M2 provides

- **Policy packs:** `packages/policy-packs/dpdp/1.0.0/pack.yaml` defines the six-right catalogue (only erasure is executable), the erasure and manual workflows, SLA placeholders (unvalidated, so no due date is set), the exception vocabulary and retention rules. Changing a pack means a new version plus `make policy-pin`.
- **Integrity:** manifest hash pinning, publishing refuses changed content, the DB blocks edits by trigger, and the registry re-hashes on load.
- **Pipeline:** OTP verification writes a `case.verified` outbox message. The worker resolves identity, then decides jurisdiction from the tenant's enabled packs and their declared applicability, then pins the case to `code@version` or routes it to manual handling.
- **Identity resolution:** conservative normalisation (IDNA, NFC, E.164, ASCII digits only) and assurance levels. Only the OTP-verified contact is VERIFIED.
- **Workflow engine:** pack transitions are enforced for actor type, permission and tenant, and unimplemented guards fail closed. An architecture test keeps regulation names out of platform code.

## What M3 provides

- **Connector SDK** (`packages/connector-sdk`): the five-operation interface, strict bounded wire models (no personal data in match attributes), an `HttpConnector` with size caps and retryability mapping, and a conformance kit.
- **Mock connectors:** a CRM and a document store with per-account data, idempotent actions, a call log and fault injection. Both pass the conformance kit.
- **Discovery:** after jurisdiction, the worker runs one job per enabled connector using **verified identifiers only**, stores pointers and fingerprints (no record contents), and retries retryable failures without duplicating. The case then moves to `DISCOVERY_COMPLETE`.
- **Staff console** (`/ops`): OIDC login (PKCE) with Redis-backed server-side sessions, a case list, case details, and source-by-source discovery results. Case reads are audited, and other tenants' cases return 404.

## What M4 provides

- **Retention engine:** the pinned pack's rules are evaluated first-match-wins in the same transaction that completes discovery. With no matching rule, the decision fails safe to `MANUAL_REVIEW`.
- **Append-only decisions:** one linear chain per record, guaranteed by the DB (one root per match, unique `supersedes_id`, no UPDATE/DELETE). CHECKs require an exception code for RETAIN and a documented reason (≥10 chars) plus the author for any analyst override.
- **Review:** staff fire pack-defined events through `/v1/cases/{id}/transitions` (version-checked). Overrides only happen under review, use the pack's exception vocabulary, and are audited. Submission is blocked while any record needs manual review.
- **Legal holds:** scoped to a case, data principal, connector or record type. A hold forces RETAIN, including on open cases already evaluated or awaiting approval, and held records can't be overridden to anything else. Releasing a hold never reverts decisions.
- **Screen 7** (`/ops/cases/{id}/retention`): per-record decisions, basis and history, change-decision form, review actions and a legal-hold form. Browser mutations go through a CSRF-guarded, allowlisted BFF proxy.

## What M5 provides

- **Submission record:** entering `PENDING_APPROVAL` records the maker, the case version and a SHA-256 of the current decision set (match, decision id, decision, exception code).
- **Approval** (`POST /v1/cases/{id}/approvals`, `Idempotency-Key` required): bound to the case version and decision-set hash (409 if either changed, including a late legal hold). The approver must differ from the submitter and must not have authored any override in the set (403). The DB also enforces `approved_by <> submitted_by` and one decision per submission. Replaying a key returns the stored response verbatim. Concurrent approvers serialise on the case row, so exactly one wins.
- **Second enforcement:** the pack guard `approval_valid_for_version` re-checks everything when APPROVE fires. The generic transitions endpoint refuses APPROVE and REJECT, so there's no maker-checker bypass.
- **Screens:** the approval queue (`/ops/approvals`, flags cases you submitted), and the approval screen with the decision set, approve/reject (a rejection needs a comment) and history. "Resume review" appears after a rejection.

## What M6 provides

- **Planning:** in the approval transaction, one task per current decision with a deterministic idempotency key. RETAIN is `SKIPPED` with its reason. The case moves to `FULFILMENT_IN_PROGRESS`.
- **Dispatch:** lock, re-check legal holds, commit `DISPATCHED`, call the connector outside any transaction with the same key on every attempt, record the execution append-only, then fetch and hash the connector's evidence. Retryable failures back off (up to 5 attempts). A crash mid-call resumes safely.
- **Proven properties:** 5 concurrent dispatches give one side effect; two 503s then success gives 3 attempts, one effect, the same key; a timeout after apply is replayed, not re-applied; a worker killed mid-call resumes without duplication; a hold placed after approval skips the deletion.
- **Screen 9** (`/ops/cases/{id}/fulfilment`): tasks, attempts, replays, evidence hashes, and retry (same key) for permanently failed tasks.

## What M7 provides

- **Verification:** each task is checked by the connector's `verify_action` *and* an independent rescan with the verified identifiers. Expected states are ABSENT, ANONYMIZED, RESTRICTED or PRESENT (for retained or held records). Results are append-only, one round per run. A connector that lies about deleting is caught and sent to `RECONCILIATION_REQUIRED`.
- **Reconciliation:** an analyst re-runs failed records as a new round with new idempotency keys. Replaying the old key would just return the old, false result.
- **Evidence package:** a deterministic ZIP with a manifest of per-file hashes, decisions and reasons, approvals, receipts and connector evidence, the verification report and a redacted audit timeline. It's stored privately in S3 under an opaque key, and the manifest hash is anchored in the audit chain. Downloads are streamed and audited, and return 404 across tenants.
- **Uploads:** size, extension, MIME type and magic bytes must agree. The filename is discarded.
- **Screens 10 and 11:** verification rounds with reconcile, the evidence package with hashes and download, and supporting-document upload.

## What M8 provides

- **Completion response:** after the evidence package, the worker composes a message with no personal data (counts per outcome and retention reasons from the pack's own labels), sends it through the notification boundary (a mock provider, refused outside local/test), records it once, and closes the case.
- **Closure guard, twice:** the pack guard `all_fulfilment_tasks_terminal`, plus a `SECURITY DEFINER` trigger that rejects `status = CLOSED` while any task is open, even for the table owner.
- **The requester's tracking page** shows "Your request is closed" with the completion response.
- **Screen 4, the dashboard:** open, needs-analyst, awaiting-approval, overdue and deadline-not-validated counts, status filters, and an SLA state per case (`UNVALIDATED` while the pack's deadlines lack legal sign-off).
- **Screen 12, the audit timeline:** every event for the case, with hash prefixes, plus "Verify hash chain" for auditors.
- **`e2e/erasure-end-to-end.spec.ts`:** the whole vertical slice through the real stack. `make logscan` fails the build if seeded identifiers, tokens or dev passwords appear in any service log.

## What M9 provides

- **Generated authorisation matrix** over every protected route: anonymous 401, no-role 403, and 404 for a full-role user from another tenant, with no data leaked. New routes are covered automatically.
- **Threat coverage index:** every threat in the model maps to tests, checked by `tests/security/test_threat_coverage.py`.
- **More hardening:** SQL-injection static rule and payload tests, credential-reference tests, security headers on all API responses, HSTS over https, and rate limits as validated settings.
- **Scanning:** `make security` and a CI `security` job (pip-audit, pnpm audit, gitleaks with a documented, value-exact allowlist).
- **Docs:** production deployment architecture, and a threat-model review with residual risks. Sign-off is pending a named owner.
