# Keycloak dev realm

**Local development and tests only.** Keycloak stands in for the production staff IdP, which is open decision D-1.

- `idprivacy-web`: confidential BFF client (authorization code + PKCE S256).
- `idprivacy-dev-cli`: public client with the password grant enabled, for smoke tests only. Never enable this pattern in a real IdP.
- `idprivacy-api`: bearer-only resource server. Tokens from both clients carry `aud=idprivacy-api` through an audience mapper.
- The users have fixed ids that match `apps/api/src/idprivacy/scripts/seed_dev.py`. `unprovisioned@example.test` exists in the IdP but not in any tenant, so it should get a 403.
- Every user's password is the dev fixture in `idprivacy-realm.json`.
