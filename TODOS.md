# TODOS

What's still open. Engineering items are worked in order. Items marked **Needs decision** wait for a product or legal call; their current stand-in behaviour is safe. Open security and tenancy decisions are tracked in full in [docs/open-decisions.md](docs/open-decisions.md).

Status: `todo` · `in progress` · `done (commit)` · `needs decision`

## Engineering follow-ups

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Record CSO finding `27c0d030f50e` (staff-API deadlock / capacity DoS) as closed | blocked (tooling) | **Fix done and verified:** `78e4ed1` (admission limit) and `5b06943` (per-user staff rate limit). `test_concurrency.py` and `test_ratelimit.py` failed before and pass after; the load test showed 0 errors at 200 concurrent users. **Closure record:** recheck run `1791153911224-5f4a66a18e4f5ce7` accepted fresh evidence at the original boundary (`deps.py:80`), but the CSO helper only records closure from a *complete* recheck (all 14 domains assessed). Close it during the next full `/cso` run (budget it with `--budget`) |
| 2 | Wider security audit: `/cso --infra`, `--supply-chain`, `--code` | todo | The first audit was partial. Fix any supported findings |
| 3 | Check that a connector supports ANONYMIZE when the decision is made, not only at fulfilment | needs decision | Today an unsupported action is never sent (`action_unsupported`), but it only fails after approval. Approval-time checking needs a connector call from the API request path |
| 4 | Completion message date uses UTC (QA ISSUE-004) | needs decision | Needs a per-tenant timezone (`tenant.data_region` exists but is unused) |
| 5 | Compose doesn't pass `IDP_KEY_PROVIDER` / `IDP_VAULT_*` and has no Vault service | todo | `.env.example` suggests a local Vault setup that can't work as written |
| 6 | No tool to re-encrypt data when switching key providers (local ↔ Vault) | needs decision | Providers only open their own `key_id`, so switching works only on an empty database. Scope (offline job vs. lazy re-wrap) is a design call |
| 7 | No command or API to move a production tenant to a new pack version | needs decision | Only `seed_dev.py` writes `tenant_policy_pack`. Who may roll out a pack, and how it's audited, is a product call |
| 8 | `/favicon.ico` returns 404 on every page (QA ISSUE-005) | todo | Cosmetic, but it shows as a console error |
| 9 | Nightly load test in CI | todo | `make load-test` exists (`tools/load/load.py`); nothing runs it on a schedule |
| 10 | Housekeeping | todo | About 7,900 load-test cases in the dev DB (reset with `make clean && make up`, which deletes all dev data, so ask first). No git remote is configured, so nothing is pushed |

## Open decisions (summary)

Full detail and stand-ins: [docs/open-decisions.md](docs/open-decisions.md).

- **Block production:** D-1 staff identity provider · D-2 tenant isolation model · D-3 Vault login method, rotation, BYOK, who may decrypt · D-4 evidence and audit retention / WORM · D-5 connector credential store · D-6 data residency · D-13 staff MFA and session policy · D-18 BFF↔API authentication (mTLS).
- **Need legal sign-off:** D-9 response deadlines per right · D-12 the 30-day post-closure grace period and its production schedule · D-14 verification strength per right · D-20 policy pack legal review · D-25 access report availability.
- **Real connectors:** D-10 upload antivirus · D-11 connector hosting for on-premise systems.
- **Lower priority (stand-ins work):** D-7, D-8, D-15, D-16, D-17, D-19, D-21, D-22, D-23, D-24, D-26, D-27.
