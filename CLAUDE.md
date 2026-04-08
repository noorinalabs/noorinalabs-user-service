# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**noorinalabs-user-service** is a standalone user authentication, authorization, and account management service for the NoorinALabs platform. It handles OAuth login, JWT token management, session lifecycle, role-based access control (RBAC), subscription tiers, and email verification. Built with FastAPI + PostgreSQL + Redis, it is designed for PII isolation and clean separation from the main isnad-graph application.

## Tech Stack

- **Python 3.12+** with **uv** as the package manager
- **PostgreSQL 16** — user data, PII isolation
- **Redis 7** — sessions, rate limiting, verification tokens
- **FastAPI** — REST API layer
- **SQLAlchemy 2.0 + Alembic** — ORM + database migrations
- **Docker Compose** — dev infrastructure services
- **pytest + pytest-asyncio** — testing framework

## Build & Development Commands

```bash
# Setup
make setup          # Install dependencies with uv
make setup-hooks    # Configure git hooks

# Infrastructure
make infra          # Start dev services (PostgreSQL, Redis)
make infra-down     # Stop dev services

# Quality
make test           # Run pytest
make lint           # Run ruff linter
make format         # Run ruff formatter
make typecheck      # Run mypy strict
make check          # All CI checks (lint + typecheck + test)

# Database
make migrate        # Run Alembic migrations
make migrate-new MSG="description"  # Create new migration
make migrate-down   # Rollback last migration
```

## Architecture

### Application layout (`src/app/`)

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI app factory |
| `config.py` | Pydantic Settings (loads `.env`), singleton via `get_settings()` |
| `dependencies.py` | Shared FastAPI dependency providers |
| `routers/` | Route modules: health, auth, users, sessions |
| `models/` | SQLAlchemy ORM models (User, Session, Role, Subscription) |
| `schemas/` | Pydantic v2 request/response schemas |
| `services/` | Business logic (auth flows, user management, RBAC) |
| `middleware/` | CORS, security headers, rate limiting |

### Infrastructure

| Component | Purpose |
|-----------|---------|
| PostgreSQL 16 | Primary user data store, PII isolation |
| Redis 7 | Session store, rate limiting, email verification tokens |
| Docker Compose | Local dev infrastructure |

## Code Conventions

- **Ruff** for linting and formatting (line length 100)
- **mypy** strict mode with pydantic plugin
- All Pydantic models use `ConfigDict(frozen=True)` for immutability
- Async throughout — all database and Redis operations are async
- Dependency injection via FastAPI `Depends()` for auth, DB sessions, Redis
- Pydantic v2 with frozen configs for all request/response schemas

## Configuration

Copy `.env.example` to `.env`. Key variables:

**Database:**
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis connection string

**Auth:**
- `JWT_SECRET` — JWT signing secret (change in production)
- `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` — Google OAuth
- `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` — GitHub OAuth
- `AUTH_OAUTH_REDIRECT_BASE_URL` — OAuth callback base URL

**Application:**
- `CORS_ORIGINS` — JSON list of allowed origins
- `RATE_LIMIT_REQUESTS_PER_MINUTE` — API rate limiting

## Team Workflow

**All work MUST be executed through the simulated team structure.** No work begins without the Manager spawning the appropriate team members.

- **Charter & rules:** `.claude/team/charter.md`
- **Active roster:** `.claude/team/roster/`
- **Feedback log:** `.claude/team/feedback_log.md`

### Team Composition

| Role | Level | Name | File |
|------|-------|------|------|
| Manager | Senior VP (Executive) | Nadia Boukhari | `roster/manager_nadia.md` |
| Tech Lead | Staff | Anya Kowalczyk | `roster/tech_lead_anya.md` |
| Engineer | Senior | Mateo Salazar | `roster/engineer_mateo.md` |
| Security Engineer | Senior | Idris Yusuf | `roster/security_engineer_idris.md` |

### Key Rules
- **Commit identity:** Each team member commits using per-commit `-c` flags with their name and `parametrization+{FirstName}.{LastName}@gmail.com` email — **never** set global/repo git config. See `.claude/team/charter.md` § Commit Identity for the full table.
- **Worktrees** are the preferred isolation method for all code-writing agents
- Manager spawns team members, creates stories/AC, and owns timelines
- Feedback flows up and down; severe feedback triggers fire-and-replace
- If the Manager receives significant negative feedback from the user, the Manager is replaced
- Team evolves toward steady state of minimal negative feedback

## Developer Tooling & Orchestration

- **gh-cli** is installed and available from the terminal
- **SSH access** is enabled from the terminal
- **GitHub Projects** — project/feature tracking and board management
- **GitHub Issues** — story/task/bug tracking (created by Manager, assigned to team members)
- **GitHub Actions** — CI/CD pipelines, automated tests, linting, deployment
- These three (Projects, Issues, Actions) are the **core orchestration layer** — do not introduce alternative tools for these concerns
- **Branching strategy:** Feature branches named `{FirstInitial}.{LastName}\{IIII}-{issue-name}` (e.g., `M.Salazar\0003-claude-md-charter-roster`) merged to `main` via PR
