COMPOSE := docker compose -f infra/compose/docker-compose.yml
TEST_DB_ENV := IDP_REQUIRE_DB=1

.PHONY: help up up-deps down clean logs ps migrate seed test test-api test-worker test-web test-e2e lint fmt typecheck contracts smoke

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

test: test-api test-worker test-web  ## Run all test suites

test-api: up-deps  ## API tests (needs Postgres)
	cd apps/api && $(TEST_DB_ENV) uv run pytest -q

test-worker:  ## Worker tests
	cd apps/worker && uv run pytest -q

test-web:  ## Web unit tests
	pnpm test:web

test-e2e:  ## Playwright against the running stack (`make up` first)
	pnpm test:e2e

lint:  ## Lint and type-check everything
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy apps/api/src apps/worker/src packages/mock-connectors/src
	pnpm lint:web

fmt:  ## Format Python
	uv run ruff check --fix .
	uv run ruff format .

contracts:  ## Regenerate contracts/openapi.json from the API
	uv run python -m idprivacy.scripts.export_openapi contracts/openapi.json

smoke:  ## End-to-end check against the running stack (Keycloak token -> API)
	./infra/compose/smoke.sh
