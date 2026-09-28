# Build context: repository root. Targets: api, worker, mock-connectors.
FROM python:3.12-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
RUN groupadd --system app && useradd --system --gid app --home /app app
WORKDIR /src
COPY pyproject.toml uv.lock .python-version ./
COPY apps/api apps/api
COPY apps/worker apps/worker
COPY packages/connector-sdk packages/connector-sdk
COPY packages/mock-connectors packages/mock-connectors
COPY packages/policy-packs packages/policy-packs
ENV IDP_POLICY_PACKS_DIR=/src/packages/policy-packs

FROM base AS api
RUN uv sync --frozen --no-dev --package idprivacy --no-editable
WORKDIR /src/apps/api
USER app
EXPOSE 8000
CMD ["uvicorn", "idprivacy.asgi:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers"]

FROM base AS worker
RUN uv sync --frozen --no-dev --package idprivacy-worker --no-editable
USER app

FROM base AS mock-connectors
RUN uv sync --frozen --no-dev --package idprivacy-mock-connectors --no-editable
USER app
EXPOSE 8100
CMD ["uvicorn", "mock_connectors.app:app", "--factory", "--host", "0.0.0.0", "--port", "8100", "--no-server-header"]
