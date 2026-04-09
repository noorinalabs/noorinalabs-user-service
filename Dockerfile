# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

FROM base AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev

FROM base AS runtime
WORKDIR /app
RUN adduser --system --no-create-home app
COPY --from=builder /app/.venv /app/.venv
COPY . .
USER app

ENV PATH="/app/.venv/bin:$PATH"

# No CMD — docker-compose.prod.yml command: is the single source of truth
# Standalone: uvicorn src.app.main:create_app --factory --host 0.0.0.0 --port 8000
