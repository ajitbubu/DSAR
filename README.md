# ID-PRIVACY DPAR/DSAR Automation

A DPDP-first platform for automating Data Principal / Data Subject rights requests. The first release is a complete **Right to Erasure** vertical slice.

- Scope, architecture, threat model and ADRs: [`docs/`](docs/)
- Milestones and acceptance criteria: [`docs/milestones.md`](docs/milestones.md)
- Open security and tenancy decisions: [`docs/open-decisions.md`](docs/open-decisions.md)

**Status:** M0 (foundations) and M1 (Data Principal intake and OTP verification) complete.

## Layout

```
apps/api                 FastAPI + shared domain package `idprivacy` (Alembic migrations here)
apps/worker              Celery workers + outbox relay (`idprivacy_worker`)
apps/web                 Next.js UI + BFF (pages arrive in M1)
packages/mock-connectors Simulated CRM / document store (filled in during M3)
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
```

Try the Data Principal flow at http://localhost:3000/r/acme. The stack runs the API with `IDP_ENV=test`, so the verify screen shows the mock OTP (development only).

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
