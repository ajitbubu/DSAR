# ADR-0002: Multi-tenancy model (MVP)

- Status: Proposed. **Final production isolation model is open decision D-2.**
- Date: 2026-09-25

## Context
The platform handles highly sensitive personal data for several organisations. Cross-tenant leakage is the worst possible failure. The production isolation requirement (shared DB vs schema vs database vs deployment per tenant) hasn't been specified and mustn't be invented.

## Decision (MVP, designed so it can be tightened)
1. **Shared database, shared schema, `tenant_id` on every tenant-owned table.** It's NOT NULL, indexed, and leads every composite index.
2. **Composite foreign keys** `(tenant_id, parent_id)` so child rows can't point into another tenant.
3. **Tenant context** comes *only* from the authenticated principal: the staff JWT → `user.tenant_id` lookup, or the DP tracking session → `request.tenant_id`. It never comes from a header, path or body param the client controls. The public intake endpoint resolves the tenant from a server-side mapping of the configured intake hostname/slug. A tenant chosen by the client is limited to *which intake form*; it grants no access.
4. **Repository layer** requires a `TenantContext` argument. No query API exists without it.
5. **Postgres Row-Level Security** on every tenant table, `USING (tenant_id = current_setting('app.tenant_id')::uuid)`, set with `SET LOCAL` per transaction. The app DB role is not the table owner and has no `BYPASSRLS`. Migrations use a separate role.
6. **Workers** receive `tenant_id` + object IDs only, and re-establish RLS context before touching data.
7. **Object storage keys** are prefixed `tenants/{tenant_id}/…`. Access always goes through the API after authz.
8. **Per-tenant encryption keys** (DEKs wrapped by a per-tenant KEK) are designed in. Custody depends on D-3.

## Consequences
+ Two independent controls (app filter + RLS) must both fail for a leak.
+ Moving to schema-per-tenant or DB-per-tenant later is mechanical, because every query already carries tenant context.
− RLS adds per-transaction `SET LOCAL`. Pooled connections must use transaction-scoped settings only (no session-level `SET`).
− Noisy-neighbour and residency isolation aren't addressed. See D-2 and D-6.

## Tests
Two seeded tenants with identical identifiers. Every endpoint is tested cross-tenant. A raw-SQL RLS test confirms a missing app filter still returns zero rows.
