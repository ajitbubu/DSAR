# ADR-0001: Monorepo layout and toolchain

- Status: Proposed
- Date: 2026-09-25

## Context
The product has a TypeScript web app, a Python API, Python workers, a shared connector SDK, policy packs, and OpenAPI contracts. The web client and the API have to stay contract-compatible.

## Decision
One repository:

```
apps/web            Next.js (App Router) + React + TS — UI + BFF
apps/api            FastAPI
apps/worker         Celery workers (imports domain code from apps/api package `idprivacy`)
packages/connector-sdk   Python package: interface, idempotency helpers, conformance kit
packages/mock-connectors FastAPI service simulating CRM + document store
packages/policy-packs    YAML packs + JSON Schema
packages/api-client      TS client generated from OpenAPI (openapi-typescript)
contracts/openapi.yaml   Source of truth, CI fails on drift vs FastAPI-generated spec
infra/compose            docker-compose.yml, Keycloak realm export, S3 stand-in init
docs/
```

- Python: `uv` workspace, Python 3.12 in containers, `ruff`, `mypy --strict` on domain packages, `pytest`.
- JS: `pnpm` workspace, Node 24 LTS in containers, `eslint`, `vitest`, `playwright`.
- `apps/api` and `apps/worker` share one Python distribution (`idprivacy`) so domain logic isn't duplicated. The worker is a different entrypoint and image target.
- `Makefile` targets: `up`, `test`, `test-e2e`, `lint`, `contracts-check`.

## Consequences
+ Atomic changes across contract, API and UI. One CI.
+ The shared domain package prevents API/worker drift.
− Two language toolchains in one repo. CI caching matters.
− The repo must be initialised as its own git repo (see open decision D-15). Today it sits inside `~/Code-base`.

## Alternatives considered
- Polyrepo: rejected. Contract drift risk, and too much overhead for an MVP.
- Nx/Turborepo for everything: too Python-unfriendly. `pnpm` + `uv` workspaces are enough.
