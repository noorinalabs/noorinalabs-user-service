"""Idempotently seed a NON-ADMIN email/password test account.

Why this exists
---------------
We need a stable, non-admin account on each environment (stg + prod) to drive
the UI in manual/automated QA — distinct credentials per environment, no admin
rights. Unlike the OAuth-only owner account elevated by ``bootstrap_admin.py``,
this account is created *from credentials alone* (email + password), so it can be
seeded unattended and — crucially — **re-seeded after a user-service DB wipe**.
Wired into the post-migrate / post-deploy hooks (mirroring the admin bootstrap),
it is recreated on every deploy, so destroying ``user_pg_data`` and redeploying
restores the test account automatically.

What this does
--------------
Reads the target credentials from ``TEST_USER_EMAIL`` / ``TEST_USER_PASSWORD``
(or ``--email`` / ``--password``) and idempotently upserts the account:

- absent  → create the user (bcrypt-hashed password, ``is_active=True``,
  ``email_verified=True``) and grant the non-admin role (default ``reader``);
- present → re-hash + update the password if one is supplied (credential
  rotation), and ensure the non-admin role is assigned;
- always ensures the role grant exists exactly once.

Deliberately NEVER grants ``admin``. The role is selectable via ``--role`` but
defaults to ``reader`` and an explicit ``admin`` is rejected — this script must
not become an admin-grant path (use ``bootstrap_admin.py`` for that).

Safety / idempotency
--------------------
- No credentials configured (``TEST_USER_EMAIL`` / ``TEST_USER_PASSWORD`` unset
  and no flags) → benign no-op, exit 0. So an unconfigured deploy step does not
  fail the deploy (parity with ``bootstrap_admin.py``'s ``user_not_found`` no-op).
- Running twice = one user, one role grant, password converged. The second run
  reports ``unchanged``.
- ``BootstrapError`` (exit 1) is reserved for genuine misconfiguration — the
  target role is missing (the roles are seeded by alembic ``0001`` so absence
  means an unmigrated DB), or ``--role admin`` was requested.

Usage
-----
    # Defaults: creds from TEST_USER_EMAIL / TEST_USER_PASSWORD, DB url from
    # the app settings (DATABASE_URL / DATABASE_* components), role = reader.
    python scripts/bootstrap_test_user.py

    # Explicit overrides:
    python scripts/bootstrap_test_user.py \
        --email qa-stg@noorinalabs.com --password 's3cret…' --role reader \
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
from src.app.utils.crypto import MAX_PASSWORD_BYTES, hash_password, verify_password

log = logging.getLogger("bootstrap_test_user")

DEFAULT_ROLE_NAME = "reader"
# Roles this script is allowed to grant. ``admin`` is intentionally excluded — a
# test account must never be elevated; bootstrap_admin.py is the only admin path.
ALLOWED_ROLES = ("reader", "researcher", "trial")

SeedStatus = Literal["created", "updated", "unchanged", "no_credentials"]


class BootstrapError(RuntimeError):
    """A genuine misconfiguration that should fail loudly (non-zero exit).

    Reserved for an unusable DB (target role missing → unmigrated) or a refused
    request (``--role admin``); never for the benign no-credentials no-op.
    """


@dataclass
class SeedResult:
    status: SeedStatus
    email: str | None = None
    role: str | None = None
    user_id: uuid.UUID | None = None


async def seed_test_user(
    db: AsyncSession, *, email: str, password: str, role_name: str
) -> SeedResult:
    """Idempotently create/update the non-admin test user with ``role_name``.

    Pure and DB-agnostic (SQLite or Postgres). Returns ``created`` /
    ``updated`` / ``unchanged``. Raises :class:`BootstrapError` if ``role_name``
    is ``admin`` or the role row is missing (unmigrated DB).
    """
    if role_name == "admin":
        msg = "Refusing to grant 'admin' to a test account — use bootstrap_admin.py."
        raise BootstrapError(msg)

    # bcrypt (4.1+) raises on inputs beyond 72 bytes rather than silently
    # truncating. Reject early with a clear diagnostic — matching the
    # /auth/register guard — so an over-long operator-set TEST_USER_PASSWORD is a
    # legible config error, not an opaque bcrypt crash mid-seed.
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        msg = f"TEST_USER_PASSWORD must not exceed {MAX_PASSWORD_BYTES} bytes (bcrypt limit)."
        raise BootstrapError(msg)

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
    if role is None:
        msg = (
            f"The {role_name!r} role does not exist — the database has not been "
            "migrated (expected from alembic 0001_initial_schema). Run "
            "`make migrate` before seeding the test user."
        )
        raise BootstrapError(msg)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    changed = False
    created = False

    if user is None:
        user = User(
            id=uuid.uuid4(),
            email=email,
            email_verified=True,  # provisioned account — skip out-of-band verify
            display_name="QA Test User",
            password_hash=hash_password(password),
            is_active=True,
        )
        db.add(user)
        await db.flush()  # assign user.id for the role grant below
        created = True
    else:
        # Converge the password (rotation) — only write when it actually differs
        # so a no-op run reports ``unchanged``.
        if not (user.password_hash and verify_password(password, user.password_hash)):
            user.password_hash = hash_password(password)
            changed = True
        if not user.is_active:
            user.is_active = True
            changed = True

    existing_grant = (
        await db.execute(
            select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
        )
    ).scalar_one_or_none()
    if existing_grant is None:
        # granted_by NULL: system-seeded, not granted by an administrator.
        db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=None))
        changed = True

    if created or changed:
        await db.commit()

    status: SeedStatus = "created" if created else ("updated" if changed else "unchanged")
    return SeedResult(status=status, email=email, role=role_name, user_id=user.id)


def _to_async_url(database_url: str) -> str:
    """Normalise a connection URL to the asyncpg driver this script uses."""
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql+psycopg2://"):
        return database_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url


async def run(database_url: str, *, email: str, password: str, role_name: str) -> SeedResult:
    """Open an async engine/session against ``database_url`` and seed the user."""
    engine = create_async_engine(_to_async_url(database_url), echo=False)
    try:
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            return await seed_test_user(
                session, email=email, password=password, role_name=role_name
            )
    finally:
        await engine.dispose()


def _resolve_email(arg_email: str | None) -> str | None:
    return arg_email or os.environ.get("TEST_USER_EMAIL") or None


def _resolve_password(arg_password: str | None) -> str | None:
    return arg_password or os.environ.get("TEST_USER_PASSWORD") or None


def _resolve_database_url(arg_url: str | None) -> str:
    if arg_url:
        return arg_url
    from src.app.config import get_settings

    return get_settings().effective_database_url


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Idempotently seed a non-admin email/password test account.",
    )
    parser.add_argument(
        "--email",
        default=None,
        help="Email of the test account. Defaults to $TEST_USER_EMAIL.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password for the test account. Defaults to $TEST_USER_PASSWORD.",
    )
    parser.add_argument(
        "--role",
        default=DEFAULT_ROLE_NAME,
        choices=ALLOWED_ROLES,
        help=f"Non-admin role to grant (default: {DEFAULT_ROLE_NAME}).",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Postgres connection URL. Defaults to the app settings (DATABASE_URL).",
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
    password = _resolve_password(args.password)

    if not email or not password:
        log.info(
            "TEST_USER_EMAIL / TEST_USER_PASSWORD not configured (and no "
            "--email/--password) — nothing to seed. No-op."
        )
        return 0

    database_url = _resolve_database_url(args.database_url)

    try:
        result = asyncio.run(run(database_url, email=email, password=password, role_name=args.role))
    except BootstrapError as exc:
        log.error("%s", exc)
        return 1

    if result.status == "created":
        log.info(
            "Created test user %s with role %s (user_id=%s).",
            result.email,
            result.role,
            result.user_id,
        )
    elif result.status == "updated":
        log.info(
            "Updated test user %s (role %s ensured; user_id=%s).",
            result.email,
            result.role,
            result.user_id,
        )
    else:
        log.info(
            "Test user %s already converged (role %s; user_id=%s) — no change.",
            result.email,
            result.role,
            result.user_id,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
