"""Idempotently grant the ``admin`` role to the bootstrap account.

Why this exists (us#159)
------------------------
The ``admin`` ROLE is seeded by alembic ``0001_initial_schema`` but **no user
is granted it**. Every user-service admin endpoint requires an admin JWT, and
the isnad-graph admin panels (user-mgmt, data, reset) all sit behind that JWT —
so without a seeded admin they 401/403 for everyone. This is a chicken-and-egg
bootstrap: granting admin normally requires an admin to call the grant endpoint.

What this does (and deliberately does NOT do)
---------------------------------------------
This script ONLY elevates an account that **already exists** — it finds the
bootstrap user by email and assigns the ``admin`` role IF NOT ALREADY ASSIGNED.

It never creates an account and never sets a credential. Account creation in
this service is OAuth-only (``find_or_create_oauth_user``); there is no
password-registration / password-login path, so a synthetic "bootstrap admin"
account with a hardcoded password would be unusable. The supported flow is:

    1. The owner logs in once via Google OAuth as the bootstrap email
       (default: ``parametrization@gmail.com``). That creates the user row.
    2. Run this script (locally, or as a post-deploy step). It grants admin.

Idempotency / safety
--------------------
- Running twice = exactly one grant (the second run reports ``already_admin``).
- No-op (exit 0) when the user does not exist yet — so it can run unattended in
  a deploy *before* the owner has ever logged in without crashing the deploy.
  Pass ``--require-user`` to make an absent user a hard error (exit 1) instead.
- ``BootstrapError`` (exit 1) is reserved for genuine misconfiguration — e.g.
  the ``admin`` role is missing, which means the DB was never migrated.

Usage
-----
    # Defaults: email from BOOTSTRAP_ADMIN_EMAIL (or parametrization@gmail.com),
    # database URL from the app settings (DATABASE_URL / DATABASE_* components).
    python scripts/bootstrap_admin.py

    # Explicit overrides:
    python scripts/bootstrap_admin.py \
        --email someone@example.com \
        --database-url postgresql+asyncpg://user:pass@host:5432/user_service
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.models.role import Role, UserRole
from src.app.models.user import User

log = logging.getLogger("bootstrap_admin")

# The account elevated by default. This is an *identifier*, not a credential —
# it selects which already-existing account to grant admin to. Override with
# --email or the BOOTSTRAP_ADMIN_EMAIL env var.
DEFAULT_ADMIN_EMAIL = "parametrization@gmail.com"

ADMIN_ROLE_NAME = "admin"

GrantStatus = Literal["granted", "already_admin", "user_not_found"]


class BootstrapError(RuntimeError):
    """A genuine misconfiguration that should fail loudly (non-zero exit).

    Distinct from the benign ``user_not_found`` no-op: this signals the database
    is not in a usable state (e.g. the ``admin`` role is missing because
    migrations never ran).
    """


@dataclass
class GrantResult:
    status: GrantStatus
    email: str
    user_id: uuid.UUID | None = None


async def grant_admin(db: AsyncSession, email: str) -> GrantResult:
    """Grant ``admin`` to the user with ``email`` if not already granted.

    Pure, idempotent, and DB-agnostic (works on SQLite or Postgres):
    - returns ``user_not_found`` (no write) when no such user exists;
    - returns ``already_admin`` (no write) when the grant already exists;
    - otherwise inserts the ``user_roles`` row and returns ``granted``.

    Raises :class:`BootstrapError` if the ``admin`` role itself is missing — the
    role is created by migration ``0001`` so its absence means an unmigrated DB.
    """
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        return GrantResult(status="user_not_found", email=email)

    admin_role = (
        await db.execute(select(Role).where(Role.name == ADMIN_ROLE_NAME))
    ).scalar_one_or_none()
    if admin_role is None:
        msg = (
            f"The {ADMIN_ROLE_NAME!r} role does not exist — the database has not "
            "been migrated (expected from alembic 0001_initial_schema). Run "
            "`make migrate` before bootstrapping the admin."
        )
        raise BootstrapError(msg)

    existing = (
        await db.execute(
            select(UserRole).where(
                UserRole.user_id == user.id,
                UserRole.role_id == admin_role.id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return GrantResult(status="already_admin", email=email, user_id=user.id)

    # granted_by is left NULL: this is the *first* admin, granted by the system
    # bootstrap rather than by an existing administrator. The FK is nullable
    # (ON DELETE SET NULL), so NULL is the correct "no granting admin" sentinel.
    db.add(UserRole(user_id=user.id, role_id=admin_role.id, granted_by=None))
    await db.commit()
    return GrantResult(status="granted", email=email, user_id=user.id)


def _to_async_url(database_url: str) -> str:
    """Normalise a connection URL to the asyncpg driver this script uses.

    Accepts the app default (``postgresql+asyncpg://``), a bare
    ``postgresql://``, or a sync ``postgresql+psycopg2://`` URL (e.g. one a
    human copied from psql) and returns an asyncpg URL. Non-postgres URLs (such
    as ``sqlite+aiosqlite://`` used by tests) are returned unchanged.
    """
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql+psycopg2://"):
        return database_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url


async def run(database_url: str, email: str) -> GrantResult:
    """Open an async engine/session against ``database_url`` and grant admin."""
    engine = create_async_engine(_to_async_url(database_url), echo=False)
    try:
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            return await grant_admin(session, email)
    finally:
        await engine.dispose()


def _resolve_email(arg_email: str | None) -> str:
    if arg_email:
        return arg_email
    return os.environ.get("BOOTSTRAP_ADMIN_EMAIL") or DEFAULT_ADMIN_EMAIL


def _resolve_database_url(arg_url: str | None) -> str:
    if arg_url:
        return arg_url
    # Reuse the app's single source of truth (reads DATABASE_URL or the
    # DATABASE_* component vars). Imported lazily so test collection never
    # triggers settings validation.
    from src.app.config import get_settings

    return get_settings().effective_database_url


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Idempotently grant the admin role to the bootstrap account.",
    )
    parser.add_argument(
        "--email",
        default=None,
        help=(
            "Email of the account to grant admin. Defaults to "
            "$BOOTSTRAP_ADMIN_EMAIL or " + DEFAULT_ADMIN_EMAIL
        ),
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres connection URL. Defaults to the app settings (DATABASE_URL).",
    )
    parser.add_argument(
        "--require-user",
        action="store_true",
        help="Exit non-zero if the target user does not exist (default: no-op exit 0).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    email = _resolve_email(args.email)
    database_url = _resolve_database_url(args.database_url)

    try:
        result = asyncio.run(run(database_url, email))
    except BootstrapError as exc:
        log.error("%s", exc)
        return 1

    if result.status == "granted":
        log.info("Granted admin to %s (user_id=%s).", result.email, result.user_id)
        return 0
    if result.status == "already_admin":
        log.info("%s is already an admin (user_id=%s) — no change.", result.email, result.user_id)
        return 0

    # user_not_found
    log.warning(
        "No account found for %s. Account creation is OAuth-only — the owner "
        "must log in once via Google OAuth as %s, then re-run this script to "
        "grant admin.",
        result.email,
        result.email,
    )
    return 1 if args.require_user else 0


if __name__ == "__main__":
    sys.exit(main())
