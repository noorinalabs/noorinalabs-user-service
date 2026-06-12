.PHONY: setup dev setup-hooks infra infra-down test lint format typecheck check migrate migrate-new migrate-down openapi-snapshot bootstrap-admin

# Setup
setup:
	uv sync

dev:
	uv sync --extra dev

setup-hooks:
	@echo "Git hooks are enforced via Claude Code org-level hooks."
	@echo "See .claude/team/charter.md § Automated Enforcement."

# Infrastructure
infra:
	docker compose -f docker-compose.dev.yml up -d

infra-down:
	docker compose -f docker-compose.dev.yml down

# Quality
test:
	ENVIRONMENT=test uv run pytest

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/

typecheck:
	uv run mypy src/

check: lint typecheck test

# Database migrations
migrate:
	uv run alembic upgrade head

migrate-new:
	uv run alembic revision --autogenerate -m "$(MSG)"

migrate-down:
	uv run alembic downgrade -1

# API surface
openapi-snapshot:
	uv run python scripts/generate_openapi_snapshot.py

# Bootstrap: idempotently grant admin to the bootstrap account (us#159).
# Account creation is OAuth-only — the owner must log in once via Google OAuth
# as the bootstrap email first; this only ELEVATES that existing account.
# Override the target via BOOTSTRAP_ADMIN_EMAIL (default parametrization@gmail.com).
bootstrap-admin:
	uv run python scripts/bootstrap_admin.py
