# TODOS

What's still open. Engineering items are worked in order. Items marked **Needs decision** wait for a product or legal call; their current stand-in behaviour is safe. Open security and tenancy decisions are tracked in full in [docs/open-decisions.md](docs/open-decisions.md).

Status: `todo` · `in progress` · `done (commit)` · `needs decision`

## Engineering follow-ups

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Record CSO finding `27c0d030f50e` (staff-API deadlock / capacity DoS) as closed | blocked (tooling) | **Fix done and verified:** `78e4ed1` (admission limit) and `5b06943` (per-user staff rate limit). `test_concurrency.py` and `test_ratelimit.py` failed before and pass after; the load test showed 0 errors at 200 concurrent users. **Closure record:** recheck run `1791153911224-5f4a66a18e4f5ce7` accepted fresh evidence at the original boundary (`deps.py:80`), but the CSO helper only records closure from a *complete* recheck (all 14 domains assessed). Close it during the next full `/cso` run (budget it with `--budget`) |
| 2 | Wider security audit: `/cso --infra`, `--supply-chain`, `--code` | done (no findings) | `--infra` run `1791154093084-430df98dace5aa1d` (covers supply chain) and `--code` run `1791154160798-175f64f320cba5bf`: **0 supported findings**. Checked: CI (push/pull_request only, read-only token, no secrets), Dockerfiles (non-root, frozen locks, no baked secrets), Compose (all ports on 127.0.0.1, nothing privileged), gitleaks allowlist (exact dev key only), parameterised SQL, no shell/eval/pickle, `yaml.safe_load`, no HTML injection sinks, safe login/logout redirects. **Remaining gaps:** git-history secrets and an OSV dependency scan (need the helper's pinned Docker scanner catalog); per-route object authorization and crypto/session were not re-traced (covered by existing tests). Leads, not findings: CI actions pinned by tag not SHA; `seaweedfs:latest` unpinned (dev only) |
| 3 | Check that a connector supports ANONYMIZE when the decision is made, not only at fulfilment | needs decision | Today an unsupported action is never sent (`action_unsupported`), but it only fails after approval. Approval-time checking needs a connector call from the API request path |
| 4 | Completion message date uses UTC (QA ISSUE-004) | needs decision | Needs a per-tenant timezone (`tenant.data_region` exists but is unused) |
| 5 | Compose doesn't pass `IDP_KEY_PROVIDER` / `IDP_VAULT_*` and has no Vault service | done | Compose now passes the four variables to every Python service (defaults keep the local provider) and has an optional dev Vault under the `vault` profile; `make vault-up` starts it and enables Transit. Verified: provisioning from shell variables creates both keys for both tenants, `vault-up` is safe to repeat, the default stack still runs on `local` |
| 6 | No tool to re-encrypt data when switching key providers (local ↔ Vault) | needs decision | Providers only open their own `key_id`, so switching works only on an empty database. Scope (offline job vs. lazy re-wrap) is a design call |
| 7 | No command or API to move a production tenant to a new pack version | needs decision | Only `seed_dev.py` writes `tenant_policy_pack`. Who may roll out a pack, and how it's audited, is a product call |
| 8 | `/favicon.ico` returns 404 on every page (QA ISSUE-005) | done | `app/favicon.ico` + `app/icon.svg` in the brand colour. Verifying it uncovered a real defect: the landing page and the 404 page were prerendered without the CSP nonce, so the browser blocked all their scripts (and Next's built-in 404 page used inline styles the CSP blocks). Fixed with a dynamic root layout and a custom `app/not-found.tsx`; `e2e/csp.spec.ts` now fails on any CSP violation or failed resource on `/`, `/r/acme` and the 404 page |
| 9 | Nightly load test in CI | done | `.github/workflows/load.yml`: nightly 02:30 UTC + manual run; staff list (to 100 users, past the old deadlock threshold), case detail, public intake, web page; fails if any stage has errors (`MAX_ERROR_PCT=0`) or p95 > 3 s, then checks `/readyz`. Compose now passes `IDP_RATE_LIMIT_STAFF_PER_USER` so the run lifts the one-account limit. Verified locally with the exact steps: all stages 0% errors, worst p95 467 ms. Takes effect once the repo has a GitHub remote |
| 10 | Housekeeping | todo | About 7,900 load-test cases in the dev DB (reset with `make clean && make up`, which deletes all dev data, so ask first). No git remote is configured, so nothing is pushed |

## Open decisions (summary)

Full detail and stand-ins: [docs/open-decisions.md](docs/open-decisions.md).

- **Block production:** D-1 staff identity provider · D-2 tenant isolation model · D-3 Vault login method, rotation, BYOK, who may decrypt · D-4 evidence and audit retention / WORM · D-5 connector credential store · D-6 data residency · D-13 staff MFA and session policy · D-18 BFF↔API authentication (mTLS).
- **Need legal sign-off:** D-9 response deadlines per right · D-12 the 30-day post-closure grace period and its production schedule · D-14 verification strength per right · D-20 policy pack legal review · D-25 access report availability.
- **Real connectors:** D-10 upload antivirus · D-11 connector hosting for on-premise systems.
- **Lower priority (stand-ins work):** D-7, D-8, D-15, D-16, D-17, D-19, D-21, D-22, D-23, D-24, D-26, D-27.
