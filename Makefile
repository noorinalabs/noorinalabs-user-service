.PHONY: setup setup-hooks infra infra-down test lint format typecheck check migrate migrate-new migrate-down

# Setup
setup:
	uv sync

setup-hooks:
	@echo "Git hooks are enforced via Claude Code org-level hooks."
	@echo "See .claude/team/charter.md § Automated Enforcement."

# Infrastructure
infra:
	docker compose up -d

infra-down:
	docker compose down

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
