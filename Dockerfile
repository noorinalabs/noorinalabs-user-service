# syntax=docker/dockerfile:1
# python:3.12-slim digest-pinned for reproducible builds + trivy-stable OS package
# baseline. Re-pin to a fresh digest when OS CVEs accumulate (target cadence: monthly
# or when CI surfaces failures). Last pin: 2026-05-19.
FROM python:3.12-slim@sha256:bf73779de6dbd030f3d189eeeb246286965832761ace318c1518300f76c0840d AS base

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

CMD ["uvicorn", "src.app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
