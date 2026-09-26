# Repository Inspection — Existing Constraints

Inspected: 2026-09-25

## Findings

| # | Finding | Consequence |
|---|---------|-------------|
| 1 | `DSAR/` was empty. No code, no lockfiles, no CI, no licence. | Greenfield. No legacy constraints on stack, layout or naming. |
| 2 | `DSAR/` is **not** its own git repository. It sits inside `/Users/ajit/Code-base`, which is a git repo (branch `main`, one commit, ~40 untracked sibling projects). | Any `git add`/`commit` run here goes to the **parent** repo. Decision D-15: run `git init` inside `DSAR/` before scaffolding (recommended), or pick another home for it. |
| 3 | Host toolchain: Python 3.14.7, Node 25.9.0 (not an LTS release), pnpm, Docker 29.8. No local Postgres or Redis. | Containers will pin **Python 3.12** (Celery, psycopg and pydantic-core wheels are most mature there) and **Node 24 LTS**. Postgres, Redis and object storage run only in Docker Compose. The host Python and Node versions don't matter to the build. |
| 4 | No existing identity provider, KMS, secrets manager, or object store is available or specified. | These stay open decisions (see `open-decisions.md`). Local dev uses stand-ins: Keycloak in Compose for OIDC, a local key provider for envelope encryption, SeaweedFS for S3 (MinIO images are no longer published). None of these stand-ins is a production choice. |
| 5 | No existing organisational policy on data residency, evidence retention, or tenant isolation was found in this repo. | Recorded as explicit decisions. They aren't assumed. |

## Deliverables produced in this phase

- `docs/product-scope.md`
- `docs/architecture/system-context.md`
- `docs/architecture/er-diagram.md`
- `docs/threat-model/threat-model.md`
- `docs/adr/0001` … `0007`
- `docs/api/openapi-outline.yaml`
- `docs/milestones.md`
- `docs/open-decisions.md`

No application code has been scaffolded. That waits for approval.
