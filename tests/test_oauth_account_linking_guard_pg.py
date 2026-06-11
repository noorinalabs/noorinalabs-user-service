"""Real-Postgres end-to-end enforcement test for the OAuth account-linking guard.

Issues #153 / #154. ``test_oauth_account_linking_guard.py`` proves the guard
against in-memory SQLite (fast, always-on). This module proves the SAME
rejection end-to-end against a REAL PostgreSQL instance — the database the
service actually runs on in production — started in a throwaway Docker
container. It exercises the genuine `oauth_accounts` insert path against
Postgres' real unique constraint / FK semantics, which is the strongest
evidence that the cross-method collision is rejected server-side (and that no
link row is persisted) rather than only under SQLite's looser behaviour.

Skip policy (the team-lead's "skip-guarded for CI flake" requirement):
- OPT-IN: only runs when ``RUN_PG_CONTAINER_TESTS=1``. CI leaves it unset, so
  the default CI `uv run pytest` stays fast and deterministic — it never pulls
  a Postgres image or starts a container.
- DEFENSIVE: even when opted in, it skips (rather than errors) if
  ``testcontainers`` is missing or Docker can't start the container — so a
  flaky/absent Docker daemon degrades to a skip, never a red build.

Run locally with:
    RUN_PG_CONTAINER_TESTS=1 ENVIRONMENT=test uv run pytest \
        tests/test_oauth_account_linking_guard_pg.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.models.oauth_account import OAuthAccount
from src.app.models.user import Base, User
from src.app.services.user import (
    AccountExistsWithDifferentMethodError,
    find_or_create_oauth_user,
)

# Opt-in gate — keeps the container out of the default (CI) test run entirely.
_PG_TESTS_ENABLED = os.getenv("RUN_PG_CONTAINER_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not _PG_TESTS_ENABLED,
    reason="Postgres container test is opt-in; set RUN_PG_CONTAINER_TESTS=1 to run.",
)


@pytest.fixture(scope="module")
def pg_url() -> str:
    """Start a throwaway Postgres container and yield an async SQLAlchemy URL.

    Skips (does not fail) if testcontainers/Docker is unavailable, so an absent
    or flaky Docker daemon degrades to a skip rather than a red build.
    """
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError:  # pragma: no cover - environment-dependent
        pytest.skip("testcontainers not installed")

    try:
        postgres = PostgresContainer("postgres:16-alpine")
        postgres.start()
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Could not start Postgres container (Docker unavailable?): {exc}")

    try:
        # testcontainers hands back a psycopg2 sync URL; swap the driver for asyncpg.
        sync_url = postgres.get_connection_url()
        async_url = sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://").replace(
            "postgresql://", "postgresql+asyncpg://"
        )
        yield async_url
    finally:
        postgres.stop()


@pytest.fixture
async def pg_session(pg_url: str) -> AsyncGenerator[AsyncSession, None]:
    """A real-Postgres async session with the ORM schema created fresh.

    Schema is built from the ORM metadata (the source of truth for the linking
    path) and dropped afterwards so each test sees a clean database.
    """
    engine = create_async_engine(pg_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            yield session
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


async def _count_links(db: AsyncSession, user_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count()).select_from(OAuthAccount).where(OAuthAccount.user_id == user_id)
    )
    return int(result.scalar_one())


class TestCrossMethodLinkingGuardPostgres:
    @pytest.mark.asyncio
    async def test_cross_provider_rejected_against_real_postgres(
        self, pg_session: AsyncSession
    ) -> None:
        """#153 — google account, github login, same verified email, REAL Postgres.

        Reject, and prove via a real Postgres query that the github link row was
        never written."""
        user = User(id=uuid.uuid4(), email="alice@example.com", email_verified=True, is_active=True)
        pg_session.add(user)
        await pg_session.flush()
        pg_session.add(OAuthAccount(user_id=user.id, provider="google", provider_account_id="g-1"))
        await pg_session.commit()

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                pg_session,
                provider="github",
                provider_account_id="gh-1",
                email="alice@example.com",
                display_name="Alice",
                avatar_url=None,
            )

        assert excinfo.value.primary_method == "google"
        # Real-Postgres proof: only the original google link exists; no github row.
        assert await _count_links(pg_session, user.id) == 1

    @pytest.mark.asyncio
    async def test_password_account_rejected_against_real_postgres(
        self, pg_session: AsyncSession
    ) -> None:
        """#154 — password account, google login, same verified email, REAL Postgres."""
        user = User(
            id=uuid.uuid4(),
            email="bob@example.com",
            email_verified=True,
            password_hash="argon2:$fakehash",
            is_active=True,
        )
        pg_session.add(user)
        await pg_session.commit()

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                pg_session,
                provider="google",
                provider_account_id="g-2",
                email="bob@example.com",
                display_name="Bob",
                avatar_url=None,
            )

        assert excinfo.value.primary_method == "password"
        assert str(excinfo.value) == "bob@example.com is already registered as password"
        # No OAuth link was attached to the password account in Postgres.
        assert await _count_links(pg_session, user.id) == 0

    @pytest.mark.asyncio
    async def test_new_email_signup_succeeds_against_real_postgres(
        self, pg_session: AsyncSession
    ) -> None:
        """Regression — a brand-new verified email still creates user + link on
        real Postgres (the guard does not over-block)."""
        result = await find_or_create_oauth_user(
            pg_session,
            provider="github",
            provider_account_id="gh-new",
            email="frank@example.com",
            display_name="Frank",
            avatar_url=None,
        )
        assert result.is_new_user is True
        assert await _count_links(pg_session, result.user.id) == 1
