# Milestone Plan — Erasure Vertical Slice

Every milestone exits only when its acceptance criteria pass in CI against Docker Compose. Security tests are written in the same milestone as the feature, not deferred.

## M0 — Foundations ✅
Scaffold the monorepo (ADR-0001) and Compose (postgres, redis, S3-compatible object storage, keycloak, mock-connectors, api, worker, web). Add the Alembic baseline with DB roles, RLS scaffolding and an append-only audit trigger. Add structured logging with a redaction processor, the KeyProvider (local dev impl) with AES-GCM envelope encryption and HMAC blind index, OIDC resource-server validation, the RBAC decorator, TenantContext, the outbox relay and CI.

**Acceptance**
- `make up` brings the stack healthy. `/readyz` is green.
- A route-inventory test fails if any route lacks a permission declaration.
- JWT negative tests pass: `alg=none`, bad signature, wrong `aud`/`iss`, expired → 401.
- RLS test: querying tenant B's rows with tenant A's context returns 0 rows, even without an app filter.
- `UPDATE audit_event` as the app role fails. Audit chain verification detects a manually altered row (done as the migrator role).
- Log redaction unit test: emails and phones in log calls come out masked.
- Booting with the mock OTP provider when `ENV=production` fails.

## M1 — Intake and identity verification ✅
Public erasure form, case ID issuance, mock OTP provider, confirm/resend, DP tracking session through the BFF, tracking screen.

**Acceptance**
- Submitting a valid form returns a display ID. Case status is `PENDING_VERIFICATION`. An audit event is written.
- The OTP is stored only as a hash. The mock provider exposes the code only through a test-only endpoint, available only when `ENV=test`.
- Brute force: attempt 6 → 429 and challenge `FAILED`. Expired → 410. Replay of a used challenge → 409.
- `GET /public/case` without a session → 401. A session for case A can't read case B.
- Input limits: extra field → 422. Over-length name → 422. Body > 64 KB → 413.
- CSRF: a BFF mutation without a valid token → 403.
- UI screens 1–3 render. Vitest covers form validation.

## M2 — Policy packs, jurisdiction and identity resolution ✅
DPDP pack v1.0.0 (rights catalogue with six rights, erasure workflow, placeholder workflows, retention rules, exception vocabulary, SLA placeholders). Pack loader with JSON-Schema validation and hash pinning. Jurisdiction decision. Identity resolution into canonical identifiers (lower-cased, normalised email; E.164 phone).

**Acceptance**
- The pack loads and validates. A tampered pack (hash mismatch) is rejected.
- A verified case gets a `JurisdictionDecision` pinned to `DPDP@1.0.0` with a rationale.
- Submitting a placeholder right (e.g. NOMINATION) → `PENDING_MANUAL_HANDLING`. No automation runs.
- Handler code has no regulation-specific branches. A grep-based architecture test forbids `"DPDP"` literals outside `policy/` and the pack files.
- Identity resolution unit tests cover normalisation edge cases.

## M3 — Connector SDK and discovery
`connector-sdk` interface plus conformance kit. Mock CRM and mock document store with seeded data for two tenants. Discovery fan-out, `DataMatch` persistence (pointers, fingerprints, non-PII attributes). Discovery results UI.

**Acceptance**
- Both mock connectors pass the conformance kit (duplicate-key replay, concurrent same-key, pagination, malformed-input rejection).
- A verified case produces matches from both sources, shown source by source in the UI.
- `data_match` rows contain no plaintext identifiers or record bodies (DB assertion).
- A malformed or oversized connector response is rejected and the job is marked failed. No partial garbage is stored.
- The discovery task is idempotent: running it twice doesn't duplicate matches.

## M4 — Retention engine and legal holds
Rule evaluation from the pack against match attributes and legal holds. Exactly one decision per match. Exception reasons. Analyst override (append-only supersession). Retention review UI.

**Acceptance**
- Every match has exactly one effective decision in {DELETE, RETAIN, RESTRICT, ANONYMIZE, MANUAL_REVIEW}.
- `RETAIN` without an exception code is impossible, blocked by both the DB CHECK and the API (422).
- An active legal hold forces `RETAIN` (or `RESTRICT`, per pack) with the hold referenced.
- An override needs `PRIVACY_ANALYST`, an exception code from the pack vocabulary and a ≥10-character reason. The history shows the superseded decision.
- A case can't go to `PENDING_APPROVAL` while any `MANUAL_REVIEW` decision is unresolved.

## M5 — Review and maker-checker approval
Case details, the analyst "submit for approval" action, the approval queue, approve/reject bound to `caseVersion` + `decisionSetSha256`.

**Acceptance**
- The same user can't submit and approve (403). The DB CHECK backs this up.
- An approver who authored any override in the set → 403.
- Approving a stale version or mismatched hash → 409.
- Replaying the same `Idempotency-Key` → identical response, one `approval` row, one set of fulfilment tasks.
- Rejection returns the case to `UNDER_REVIEW` with the comment audited.
- The authz matrix covers each role × each approval endpoint, including cross-tenant.

## M6 — Fulfilment orchestration
Task generation from approved decisions, idempotency keys, dispatch with retry/backoff, connector execution records and evidence capture. Fulfilment execution UI plus manual retry.

**Acceptance**
- Five concurrent dispatches of the same task → exactly one side effect at the mock connector, verified via the mock's call log.
- Fault injection (the mock returns 503 twice) → task succeeds on attempt 3 with the same key. Three `connector_execution` rows.
- Fault injection (the mock times out after applying) → retry returns the original result. There's still one deletion.
- `RETAIN` decisions → task `SKIPPED` with reason, no connector call.
- A worker killed mid-dispatch (simulated) → the resumed task completes without duplication.

## M7 — Verification and evidence
Rescan via `discover`, `verify_action`, reconciliation into `VerificationResult`, evidence package ZIP with manifest hashes, S3 storage, streamed download. Verification and evidence UIs, upload validation.

**Acceptance**
- After fulfilment: deleted matches are absent on rescan, anonymised ones carry no identifiers, and retained/restricted ones are present as expected. All `PASS`.
- A mock that "lies" (reports success without deleting) → `FAIL` → `RECONCILIATION_REQUIRED`.
- The package contains manifest, receipts, decisions and reasons, approvals, redacted audit timeline, and verification report. Recomputed hashes match the manifest. The manifest hash appears in the audit chain.
- A download without the right role or from another tenant → 404. A successful download is audited.
- Upload negatives: wrong magic bytes → 415, oversize → 413, disallowed extension → 415. The stored key never contains the original filename.

## M8 — Communication, closure and E2E
Completion response to the DP (mock channel), the closure guard, audit timeline UI and ops dashboard SLA indicators.

**Acceptance**
- Closure is blocked while any task is non-terminal (service 409 and DB trigger).
- The DP tracking screen shows the completion response.
- **Playwright E2E:** submit → OTP → discovery → review with one override → separate approver approves → fulfilment → verification → evidence download → DP sees completion → case `CLOSED`.
- Log-scan over the E2E run: zero seeded identifiers appear in any container log.

## M9 — Hardening
Full negative security suite (threat model §5), CSP and security headers, rate-limit tuning, dependency and secret scanning in CI, and production deployment doc updated with the resolved decisions.

**Acceptance**
- Every threat-model test listed in §5 exists and passes.
- `pip-audit` / `pnpm audit` / gitleaks run clean, or findings are triaged.
- Threat model revisited, with residual risks signed off by the named owner.
