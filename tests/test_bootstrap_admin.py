"""Tests for the idempotent admin-bootstrap script (us#159).

The grant logic is exercised against a REAL in-memory SQLite database (always
on, fast, deterministic) so the idempotency / no-op / no-crash guarantees are
proven by real SQL, not by a mock. A second module-level class re-proves the
same grant end-to-end against a throwaway Postgres container — opt-in and
skip-guarded (``RUN_PG_CONTAINER_TESTS=1``) so the default CI run stays fast,
mirroring ``test_oauth_account_linking_guard_pg.py``.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from scripts.bootstrap_admin import (
    DEFAULT_ADMIN_EMAIL,
    BootstrapError,
    GrantResult,
    _resolve_database_url,
    _resolve_email,
    _to_async_url,
    grant_admin,
    main,
    parse_args,
)
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User


# ---------------------------------------------------------------------------
# In-memory SQLite fixtures (always on) — mirrors the non-PG linking-guard test.
# ---------------------------------------------------------------------------
@pytest.fixture
async def db_engine():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:  # type: ignore[no-untyped-def, type-arg]
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


async def _seed_admin_role(db: AsyncSession) -> Role:
    role = Role(id=uuid.uuid4(), name="admin", description="Full platform administration access")
    db.add(role)
    await db.commit()
    return role


async def _seed_user(db: AsyncSession, email: str) -> User:
    user = User(id=uuid.uuid4(), email=email, email_verified=True, is_active=True)
    db.add(user)
    await db.commit()
    return user


async def _count_admin_grants(db: AsyncSession, user_id: uuid.UUID, role_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(UserRole)
        .where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    return int(result.scalar_one())


# ---------------------------------------------------------------------------
# grant_admin — the core idempotent logic
# ---------------------------------------------------------------------------
class TestGrantAdmin:
    @pytest.mark.asyncio
    async def test_grants_admin_to_existing_user(self, db_session: AsyncSession) -> None:
        role = await _seed_admin_role(db_session)
        user = await _seed_user(db_session, "parametrization@gmail.com")

        result = await grant_admin(db_session, "parametrization@gmail.com")

        assert result.status == "granted"
        assert result.user_id == user.id
        assert await _count_admin_grants(db_session, user.id, role.id) == 1

    @pytest.mark.asyncio
    async def test_idempotent_running_twice_grants_once(self, db_session: AsyncSession) -> None:
        role = await _seed_admin_role(db_session)
        user = await _seed_user(db_session, "owner@example.com")

        first = await grant_admin(db_session, "owner@example.com")
        second = await grant_admin(db_session, "owner@example.com")

        assert first.status == "granted"
        assert second.status == "already_admin"
        # Exactly one grant row despite two runs — the composite PK + the
        # check-before-insert both protect against a duplicate.
        assert await _count_admin_grants(db_session, user.id, role.id) == 1

    @pytest.mark.asyncio
    async def test_no_op_when_already_admin(self, db_session: AsyncSession) -> None:
        role = await _seed_admin_role(db_session)
        user = await _seed_user(db_session, "owner@example.com")
        # Pre-grant admin out-of-band, then assert the script reports no change.
        db_session.add(UserRole(user_id=user.id, role_id=role.id, granted_by=None))
        await db_session.commit()

        result = await grant_admin(db_session, "owner@example.com")

        assert result.status == "already_admin"
        assert await _count_admin_grants(db_session, user.id, role.id) == 1

    @pytest.mark.asyncio
    async def test_no_crash_when_user_absent(self, db_session: AsyncSession) -> None:
        await _seed_admin_role(db_session)

        result = await grant_admin(db_session, "nobody@example.com")

        assert result == GrantResult(status="user_not_found", email="nobody@example.com")

    @pytest.mark.asyncio
    async def test_raises_when_admin_role_missing(self, db_session: AsyncSession) -> None:
        # User exists but the admin role was never seeded (unmigrated DB).
        await _seed_user(db_session, "owner@example.com")

        with pytest.raises(BootstrapError):
            await grant_admin(db_session, "owner@example.com")


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------
class TestToAsyncUrl:
    def test_asyncpg_unchanged(self) -> None:
        url = "postgresql+asyncpg://u:p@h:5432/db"
        assert _to_async_url(url) == url

    def test_bare_postgres_gets_asyncpg(self) -> None:
        assert _to_async_url("postgresql://u:p@h:5432/db") == "postgresql+asyncpg://u:p@h:5432/db"

    def test_psycopg2_swapped_to_asyncpg(self) -> None:
        assert _to_async_url("postgresql+psycopg2://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"

    def test_sqlite_unchanged(self) -> None:
        assert _to_async_url("sqlite+aiosqlite://") == "sqlite+aiosqlite://"


# ---------------------------------------------------------------------------
# CLI / resolution
# ---------------------------------------------------------------------------
class TestResolution:
    def test_email_defaults_to_constant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BOOTSTRAP_ADMIN_EMAIL", raising=False)
        assert _resolve_email(None) == DEFAULT_ADMIN_EMAIL
        assert DEFAULT_ADMIN_EMAIL == "parametrization@gmail.com"

    def test_email_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "env@example.com")
        assert _resolve_email(None) == "env@example.com"

    def test_email_arg_beats_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "env@example.com")
        assert _resolve_email("arg@example.com") == "arg@example.com"

    def test_database_url_arg_short_circuits(self) -> None:
        # An explicit arg must not touch app settings at all.
        assert _resolve_database_url("postgresql://x/y") == "postgresql://x/y"

    def test_parse_args_defaults(self) -> None:
        args = parse_args([])
        assert args.email is None
        assert args.database_url is None
        assert args.require_user is False
        assert args.verbose is False

    def test_parse_args_require_user(self) -> None:
        assert parse_args(["--require-user"]).require_user is True


# ---------------------------------------------------------------------------
# main() exit codes — drive the whole script against in-memory SQLite.
# ---------------------------------------------------------------------------
# main() drives its OWN engine via run(), so these use a shared on-disk SQLite
# file (not in-memory, which is per-connection) so the seed and the script see
# the same database.
class TestMainExitCodes:
    @staticmethod
    async def _create_schema_and_seed(url: str, *, seed_user: str | None) -> None:
        engine = create_async_engine(url, echo=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            session_factory = async_sessionmaker(engine, expire_on_commit=False)
            async with session_factory() as s:
                await _seed_admin_role(s)
                if seed_user is not None:
                    await _seed_user(s, seed_user)
        finally:
            await engine.dispose()

    def test_granted_exits_zero(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        url = f"sqlite+aiosqlite:///{tmp_path / 'bootstrap.db'}"
        asyncio.run(self._create_schema_and_seed(url, seed_user="owner@example.com"))

        assert main(["--email", "owner@example.com", "--database-url", url]) == 0

    def test_user_absent_no_op_exits_zero(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        url = f"sqlite+aiosqlite:///{tmp_path / 'bootstrap.db'}"
        asyncio.run(self._create_schema_and_seed(url, seed_user=None))

        # Default: absent user is a clean no-op (deploy-safe).
        assert main(["--email", "ghost@example.com", "--database-url", url]) == 0
        # Strict mode: absent user is a hard error.
        assert main(["--email", "ghost@example.com", "--database-url", url, "--require-user"]) == 1


# ---------------------------------------------------------------------------
# Real-Postgres proof (opt-in, skip-guarded). Mirrors the linking-guard PG test.
# ---------------------------------------------------------------------------
_PG_TESTS_ENABLED = os.getenv("RUN_PG_CONTAINER_TESTS") == "1"

pg_only = pytest.mark.skipif(
    not _PG_TESTS_ENABLED,
    reason="Postgres container test is opt-in; set RUN_PG_CONTAINER_TESTS=1 to run.",
)


@pytest.fixture(scope="module")
def pg_url() -> str:  # type: ignore[misc]
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
        sync_url = postgres.get_connection_url()
        async_url = sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://").replace(
            "postgresql://", "postgresql+asyncpg://"
        )
        yield async_url
    finally:
        postgres.stop()


@pytest.fixture
async def pg_session(pg_url: str) -> AsyncGenerator[AsyncSession, None]:
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


@pg_only
class TestGrantAdminPostgres:
    @pytest.mark.asyncio
    async def test_grant_then_idempotent_on_real_postgres(self, pg_session: AsyncSession) -> None:
        role = await _seed_admin_role(pg_session)
        user = await _seed_user(pg_session, "parametrization@gmail.com")

        first = await grant_admin(pg_session, "parametrization@gmail.com")
        second = await grant_admin(pg_session, "parametrization@gmail.com")

        assert first.status == "granted"
        assert second.status == "already_admin"
        assert await _count_admin_grants(pg_session, user.id, role.id) == 1
