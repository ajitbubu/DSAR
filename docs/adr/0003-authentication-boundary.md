# ADR-0003: Authentication and authorization boundary

- Status: Proposed. **Production IdP and MFA policy are open decisions D-1 / D-13.**
- Date: 2026-09-25

## Context
There are two very different principals. Staff are long-lived org users with roles. Data Principals are anonymous members of the public who prove control of an identifier for one case. We mustn't build custom authentication or cryptography.

## Decision

### Staff
- **OIDC Authorization Code + PKCE** against an external IdP. Keycloak runs in Compose for local dev and tests only.
- `apps/web` is a **BFF**. It completes the OIDC flow server-side (Auth.js / `openid-client`), stores tokens server-side, and gives the browser only an httpOnly, `Secure`, `SameSite=Strict` session cookie.
- The BFF calls the API with the user's access token as a `Bearer` header. **The API is an OAuth2 resource server.** It validates signature via JWKS, `iss`, `aud`, `exp`/`nbf` and the `alg` allowlist using a maintained library.
- Authorization happens **in the API**, never only in the UI. Roles (`TENANT_ADMIN`, `PRIVACY_ANALYST`, `APPROVER`, `AUDITOR`) are stored in the platform DB per tenant, keyed by `(idp_issuer, idp_subject)`. We deliberately don't trust IdP group claims for roles in v1, which avoids coupling to the IdP's schema (revisit in D-1).
- Every route declares its required permission. A test enumerates all routes and fails if any lacks a declaration.

### Data Principal
- There's no account. Submitting a request creates an `IdentityVerification` challenge. The OTP is sent through the `OtpProvider` interface (mock in v1) and stored as a hash only.
- Successful confirmation creates a **server-side tracking session** (opaque random 256-bit token from `secrets`, stored hashed, bound to `tenant_id` + `request_id`, short TTL, sliding). The BFF sets it as an httpOnly cookie. It grants read access to that one case plus cancel. Nothing else.
- The display ID is never an authenticator.
- **Implemented in M1:** the API resolves the tenant for public routes from an opaque handle (intake slug, challenge id, or session-token hash) through narrow `SECURITY DEFINER` functions, then runs under normal RLS. The OTP is stored as a keyed HMAC (the key sits outside the DB). The challenge row is locked `FOR UPDATE` so concurrent guesses are counted exactly. The session token is stored as SHA-256, with a 30-minute sliding idle expiry and a 24-hour absolute expiry.

### BFF → API service credential (public routes)
Public Data Principal routes have no end-user bearer token, so the API requires a **BFF service credential** (`X-Internal-Auth`, a pre-shared secret compared in constant time). This keeps the API non-browser-facing and lets it trust the BFF-supplied `X-Client-IP` for rate limiting. The pre-shared secret is an MVP stand-in; production should use mTLS or workload identity (decision D-18).

### Staff sessions (implemented M3)
- The BFF uses `openid-client` (authorization code + PKCE S256, state, nonce, ID-token validation). The OIDC transaction lives in a 10-minute httpOnly cookie.
- Tokens live in **Redis**, keyed by SHA-256 of an opaque 256-bit session id, with an 8-hour absolute lifetime. The browser only holds the id (`__Host-idp_staff`). Access tokens are refreshed server-side.
- The staff session cookie is `SameSite=Lax`, because the login redirect chain starts at the IdP (cross-site). State changes are still protected by the double-submit CSRF token plus the Origin and Sec-Fetch-Site checks. Logout is CSRF-protected and ends the IdP session.
- Post-login return targets are restricted to `/ops/...` after URL normalisation, which prevents open redirects.

### CSRF
Cookie-authenticated state changes (staff and DP) go through the BFF, which enforces a double-submit CSRF token plus `Origin`/`Sec-Fetch-Site` checks. The API itself is bearer-only, so it isn't CSRF-exposed.

### Service-to-service
Worker → connectors use per-connector credentials resolved from the secret backend (D-5). Mocks use dev tokens from env.

## Consequences
+ No custom auth. Tokens never touch browser JS.
+ Authz is testable in the API in isolation.
− The BFF is a required hop. Direct API access from browsers is intentionally unsupported.
