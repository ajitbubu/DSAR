# Threat Model — ID-PRIVACY DPAR/DSAR Automation (v1 erasure slice)

Method: STRIDE per trust boundary, plus privacy-specific (LINDDUN-lite) concerns. Status: **draft**. Revisit at every milestone exit.

## 1. Assets

| Asset | Sensitivity | Why |
|---|---|---|
| Requester identifiers (email, phone, customer IDs) | High (PII) | Can be linked across systems. The point of the platform. |
| Discovery results (which systems hold data about whom) | High | Reveals relationships, e.g. customer of X, employee of Y. |
| Destructive-action authority | Critical | A misused erasure is irreversible data loss or evidence destruction. |
| Evidence packages | High | Legal proof of compliance. Must be complete and tamper-evident. |
| Audit log | High (integrity) | Accountability. Must be append-only. |
| Connector credentials | Critical | Access to customer production systems. |
| OTP codes, session tokens | High | Account-less DP access to a case. |
| Encryption keys | Critical | Protect every item above. |

## 2. Trust boundaries

- **TB1** Internet → `web` (DP anonymous plus OTP session. Staff via SSO.)
- **TB2** `web` BFF → `api` (server-to-server, bearer token)
- **TB3** `api`/`worker` → Postgres, Redis, object storage
- **TB4** `worker` → connectors → customer systems (outbound, untrusted responses)
- **TB5** `api` → OTP / notification providers
- **TB6** Tenant A ↔ Tenant B (logical, inside every data store)
- **TB7** Platform operators ↔ tenant data

## 3. Threats and mitigations

| ID | Boundary | STRIDE | Threat | Mitigation (v1) | Test |
|---|---|---|---|---|---|
| T-01 | TB1 | S | Attacker submits erasure for someone else's identity (malicious erasure) | Case can't progress past `PENDING_VERIFICATION` without OTP to the identifier being erased. Verification strength is set in the policy pack. Nothing destructive happens before analyst review **and** separate approval. | E2E: unverified case never reaches discovery. |
| T-02 | TB1 | S | OTP brute force | 6-digit OTP, hash stored (never plaintext), max attempts per challenge (pack-configured, default 5), expiry (default 10 min), per-challenge and per-IP rate limits in Redis, constant-time compare. | Negative: 6th attempt → 429/locked. Expired → 410. |
| T-03 | TB1 | S/R | OTP replay or challenge reuse | A challenge is single-use and moves to `VERIFIED` atomically (`UPDATE … WHERE status='PENDING'`). A second confirm → 409. | Negative replay test. |
| T-04 | TB1 | I | Case enumeration via display ID | The display ID is non-sequential and **not an authenticator**. Tracking requires an OTP-established session bound to `request_id`. Public endpoints return uniform responses and timing. | Negative: valid display ID without session → 404 (not 403). |
| T-05 | TB1 | I | PII or tokens in URLs → logs, Referer, history | No PII or tokens in path or query. Case access uses cookie sessions. Evidence downloads stream through the API (no presigned URLs, D-8). `Referrer-Policy: no-referrer`. | Lint rule plus a log-scan test. |
| T-06 | TB1 | T | CSRF on cookie-authenticated mutations | `SameSite=Strict` session cookies, double-submit CSRF token checked by the BFF on every non-GET, `Origin`/`Sec-Fetch-Site` check. API rejects requests without the BFF's bearer token. | Negative: missing or mismatched CSRF token → 403. |
| T-07 | TB1 | T/E | XSS steals the session or triggers approvals | React escaping, strict CSP (nonce-based, no `unsafe-inline`), httpOnly cookies, no `dangerouslySetInnerHTML`, tokens never reach browser JS. | CSP header test. |
| T-08 | TB1/TB2 | E | IDOR/BOLA: staff user reads or acts on a case they shouldn't | Every repository query takes `TenantContext`. Object fetch = `WHERE tenant_id = :ctx AND id = :id`. Role checked per operation via a policy decorator. Not-found and not-authorised both return 404. | Negative matrix: every protected route × {no auth, wrong role, other tenant}. |
| T-09 | TB6 | I/T | Cross-tenant data access through a missed filter | (1) Tenant scoping in the repository layer. (2) **Postgres RLS** on every tenant table, using `SET LOCAL app.tenant_id` per transaction (defence in depth; final model is D-2). (3) Composite FKs. (4) Worker tasks carry `tenant_id` and re-establish context. | Cross-tenant test fixture with two tenants and identical data. RLS test runs raw SQL without the filter. |
| T-10 | TB2 | S | Forged or expired staff JWT, algorithm confusion | API validates with a maintained library (Authlib/PyJWT): JWKS, pinned `alg` allowlist (RS256/ES256), `iss`, `aud`, `exp`, `nbf`. No custom auth. | Negative: `alg=none`, wrong `aud`, expired, bad signature → 401. |
| T-11 | TB2 | E | Maker-checker bypass (self-approval, approval of stale state) | DB `CHECK approved_by <> submitted_by`. Service rejects an approver who authored any override. Approval binds `case_version` + `decision_set_sha256`, and any later change invalidates it. Approve requires the `APPROVER` role and an `Idempotency-Key`. | Negative: self-approval → 403. Stale version → 409. Replayed approval → same result, no duplicate tasks. |
| T-12 | TB4 | T | Duplicate destructive actions on retry | Deterministic idempotency key per (tenant, task, action, decision). Unique constraint. Task state `DISPATCHED` is committed before the call. Connector SDK contract requires key honouring. Conformance kit tests it. | Test: dispatch ×5 concurrently → connector records 1 execution. |
| T-13 | TB4 | T/I | Malicious or compromised connector returns forged evidence or injection payloads | Connector responses are validated against strict Pydantic schemas with size limits. Verification uses an independent rescan, not just the connector's claim. Evidence is hashed on receipt. | Fuzz or malformed-response tests. |
| T-14 | TB4 | I | Connector credential leakage | Credentials are referenced by secret handle, never stored in DB plaintext, never logged. Secret backend is D-5. v1 mocks use per-connector static dev tokens from env. | Log-scan test. |
| T-15 | TB3 | I | DB or backup compromise exposes PII | Application-layer envelope encryption of identifier fields (`cryptography` AES-GCM via a KeyProvider). Blind indexes via HMAC-SHA256. Discovery stores pointers and hashes, not record content. Key custody is D-3. | Unit: ciphertext round-trip. DB rows contain no plaintext email. |
| T-16 | TB3 | T/R | Audit log tampering or deletion | `audit_writer` role has INSERT only. The app role has no UPDATE/DELETE on `audit_event`. A trigger raises on UPDATE/DELETE. A per-tenant hash chain gets periodic verification (`/audit/verify`). External anchoring is a later option. | Negative: UPDATE as app role fails. Chain verification detects an edited row. |
| T-17 | TB1 | D | Oversized or flooding requests | Body size limits at the proxy and in FastAPI (e.g. 64 KB JSON, file limit per D-10). Field length limits in schemas. Rate limits on public endpoints. Pagination caps. | Negative: 65 KB body → 413. 10 000-char name → 422. |
| T-18 | TB1 | T/E | Malicious file upload (supporting documents, analyst evidence) | Allowlist of extension + declared MIME + **magic-byte** signature (e.g. PDF, PNG, JPEG), max size, filename discarded (server-generated key), stored in a private bucket outside any web path, served as `Content-Disposition: attachment` with `X-Content-Type-Options: nosniff`. AV scanning is D-10. | Negative: `.pdf` with PNG bytes → 415. Polyglot → reject. Over size → 413. |
| T-19 | all | I | PII in logs, traces, error pages | Structured JSON logging with a redaction processor (key denylist plus regex for email/phone), Pydantic models marked `SecretStr`/`repr=False`, generic error responses, no stack traces to clients. | Log-scan test over the full E2E run. |
| T-20 | TB5 | S | Mock OTP provider leaks codes in prod | The mock provider is only registered when `ENV in {local,test}`. Startup fails if mock providers are configured in a non-dev env. | Unit: prod config with mock → boot fails. |
| T-21 | TB7 | I/E | Operator browses tenant PII | No standing operator access to tenant data. DB break-glass is out of band. Production access model is D-7. | — (process) |
| T-22 | policy | T | Tampered or silently changed policy pack changes legal outcome | Packs are immutable once published. `content_sha256` is stored. Each case pins pack id + version at jurisdiction time. Pack changes need a new version. | Unit: hash mismatch → load fails. |
| T-23 | privacy | I | The platform itself becomes a honeypot of erased-person data | Minimise: after closure, keep only what evidence requires. Identifiers in evidence are hashed or masked. Post-closure PII retention in the platform is D-12. | — |
| T-24 | TB2 | T | Mass assignment / over-posting (e.g. setting `status` via API) | Separate request and response schemas with `extra="forbid"`. Status changes only via transition endpoints. | Negative: extra field → 422. |
| T-25 | TB3 | T | SQL injection | SQLAlchemy parameterised queries only. A lint rule forbids `text()` with f-strings. | Static check plus injection payload tests. |

## 4. Residual risks / explicit non-goals for v1

- Identity verification strength is limited to OTP possession. It doesn't prove the requester *is* the person, only that they control the identifier. That's acceptable for DPDP erasure of data linked to that identifier. Higher-assurance verification (KYC, document checks) is a future policy-pack option.
- The evidence hash chain is tamper-evident, not tamper-proof, until external anchoring or WORM storage is decided (D-4).
- Mock connectors don't exercise real authentication or network failure modes beyond simulated faults.

## 5. Security test suite (required before M9 exit)

- `tests/security/test_authz_matrix.py`: every route × {anonymous, each role, other tenant}.
- `test_idor.py`, `test_cross_tenant_rls.py`, `test_csrf.py`, `test_jwt_validation.py`
- `test_otp_bruteforce_replay.py`, `test_approval_maker_checker.py`, `test_idempotent_dispatch.py`
- `test_input_limits.py` (malformed, oversized, extra fields), `test_upload_validation.py`
- `test_audit_append_only.py`, `test_log_redaction.py`
