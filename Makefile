COMPOSE := docker compose -f infra/compose/docker-compose.yml
TEST_DB_ENV := IDP_REQUIRE_DB=1

.PHONY: help up up-deps down clean logs ps migrate seed test test-api test-worker test-web test-e2e test-connectors lint fmt typecheck contracts smoke policy-pin policy-schema logscan security purge-reports minimise-closed vault-provision coverage

help:  ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

up:  ## Build and start the full stack, wait until healthy
	$(COMPOSE) up -d --build --wait

up-deps:  ## Start Postgres and Redis (enough for the Python test suites)
	$(COMPOSE) up -d --wait postgres redis

down:  ## Stop the stack (keeps volumes)
	$(COMPOSE) down

clean:  ## Stop the stack and delete volumes
	$(COMPOSE) down -v

logs:  ## Tail logs
	$(COMPOSE) logs -f --tail=100

ps:  ## Show service status
	$(COMPOSE) ps

test: test-api test-worker test-connectors test-web  ## Run all test suites

test-api: up-deps  ## API tests (needs Postgres)
	cd apps/api && $(TEST_DB_ENV) uv run pytest -q

test-worker:  ## Worker tests
	cd apps/worker && uv run pytest -q

test-connectors:  ## Connector SDK + mock connector conformance
	uv run pytest -q packages/connector-sdk/tests
	uv run pytest -q packages/mock-connectors/tests

test-web:  ## Web unit tests
	pnpm test:web

test-e2e:  ## Playwright against the running stack (`make up` first)
	pnpm test:e2e

# Coverage floors (fail below): stop regressions; raise them as tests are added.
COV_API := 90
COV_WORKER := 45
COV_CONNECTORS := 90
COV_FLAGS := --cov-report=term-missing:skip-covered

coverage: up-deps  ## Tests with coverage; fails below each suite's floor
	cd apps/api && $(TEST_DB_ENV) uv run pytest -q --cov=idprivacy $(COV_FLAGS) --cov-fail-under=$(COV_API)
	cd apps/worker && uv run pytest -q --cov=idprivacy_worker $(COV_FLAGS) --cov-fail-under=$(COV_WORKER)
	uv run pytest -q packages/connector-sdk/tests packages/mock-connectors/tests --cov=idprivacy_connector_sdk --cov=mock_connectors $(COV_FLAGS) --cov-fail-under=$(COV_CONNECTORS)
	pnpm coverage:web

lint:  ## Lint and type-check everything
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy apps/api/src apps/worker/src packages/mock-connectors/src packages/connector-sdk/src
	pnpm lint:web

fmt:  ## Format Python
	uv run ruff check --fix .
	uv run ruff format .

purge-reports:  ## Delete expired or used-up access reports (D-25); run daily
	$(COMPOSE) run --rm --no-deps migrate python -m idprivacy.scripts.purge_reports

minimise-closed:  ## Shred requester identifiers of cases closed past their grace period (D-12); run daily
	$(COMPOSE) run --rm --no-deps migrate python -m idprivacy.scripts.minimise_closed

vault-provision:  ## Create each tenant's Vault Transit keys (D-3); run after adding a tenant
	$(COMPOSE) run --rm --no-deps migrate python -m idprivacy.scripts.vault_provision

policy-pin:  ## Pin a pack's hash in the manifest: make policy-pin PACK=packages/policy-packs/dpdp/1.0.0/pack.yaml
	uv run python -m idprivacy.scripts.policy_packs pin $(PACK)

policy-schema:  ## Regenerate the policy-pack JSON Schema
	uv run python -m idprivacy.scripts.policy_packs schema

contracts:  ## Regenerate contracts/openapi.json from the API
	uv run python -m idprivacy.scripts.export_openapi contracts/openapi.json

security:  ## Dependency audits (pip-audit, pnpm audit) and secret scan (gitleaks)
	uv export --all-packages --no-dev --no-emit-workspace --no-hashes -q -o .requirements.audit.txt
	uvx pip-audit -r .requirements.audit.txt --disable-pip --no-deps --progress-spinner off
	rm -f .requirements.audit.txt
	pnpm audit --prod
	docker run --rm -v "$(CURDIR):/repo" zricethezav/gitleaks:latest git /repo --no-banner --redact --config /repo/.gitleaks.toml

logscan:  ## Fail if seeded identifiers, tokens or passwords appear in any service log
	./infra/compose/logscan.sh

smoke:  ## End-to-end check against the running stack (Keycloak token -> API)
	./infra/compose/smoke.sh
