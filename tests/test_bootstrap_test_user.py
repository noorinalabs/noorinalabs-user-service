"""Tests for the idempotent non-admin test-user seed script.

The seed logic is exercised against a REAL in-memory SQLite database (always on,
fast, deterministic) so the create / update / no-op idempotency and the
never-grant-admin guarantee are proven by real SQL, not mocks. Mirrors the
structure of ``test_bootstrap_admin.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from scripts.bootstrap_test_user import (
    BootstrapError,
    _resolve_email,
    _resolve_password,
    main,
    seed_test_user,
)
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User
from src.app.utils.crypto import verify_password

ROLE_NAMES = ("admin", "reader", "researcher", "trial")


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


async def _seed_roles(db: AsyncSession) -> dict[str, uuid.UUID]:
    ids: dict[str, uuid.UUID] = {}
    for name in ROLE_NAMES:
        role = Role(id=uuid.uuid4(), name=name, description=f"{name} role")
        db.add(role)
        ids[name] = role.id
    await db.commit()
    return ids


async def _user_by_email(db: AsyncSession, email: str) -> User | None:
    return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()


async def _count_grants(db: AsyncSession, user_id: uuid.UUID, role_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count())
        .select_from(UserRole)
        .where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    return int(result.scalar_one())


class TestSeedTestUser:
    @pytest.mark.asyncio
    async def test_creates_non_admin_user(self, db_session: AsyncSession) -> None:
        roles = await _seed_roles(db_session)

        result = await seed_test_user(
            db_session, email="qa@example.com", password="hunter2hunter2", role_name="reader"
        )

        assert result.status == "created"
        user = await _user_by_email(db_session, "qa@example.com")
        assert user is not None
        assert user.is_active is True
        assert user.password_hash and verify_password("hunter2hunter2", user.password_hash)
        # reader granted, admin NOT granted
        assert await _count_grants(db_session, user.id, roles["reader"]) == 1
        assert await _count_grants(db_session, user.id, roles["admin"]) == 0

    @pytest.mark.asyncio
    async def test_idempotent_second_run_unchanged(self, db_session: AsyncSession) -> None:
        roles = await _seed_roles(db_session)
        first = await seed_test_user(
            db_session, email="qa@example.com", password="pw-aaaaaaaa", role_name="reader"
        )
        second = await seed_test_user(
            db_session, email="qa@example.com", password="pw-aaaaaaaa", role_name="reader"
        )
        assert first.status == "created"
        assert second.status == "unchanged"
        user = await _user_by_email(db_session, "qa@example.com")
        assert user is not None
        assert await _count_grants(db_session, user.id, roles["reader"]) == 1

    @pytest.mark.asyncio
    async def test_rotates_password_on_change(self, db_session: AsyncSession) -> None:
        await _seed_roles(db_session)
        await seed_test_user(
            db_session, email="qa@example.com", password="old-password", role_name="reader"
        )
        result = await seed_test_user(
            db_session, email="qa@example.com", password="new-password", role_name="reader"
        )
        assert result.status == "updated"
        user = await _user_by_email(db_session, "qa@example.com")
        assert user is not None
        assert verify_password("new-password", user.password_hash or "")
        assert not verify_password("old-password", user.password_hash or "")

    @pytest.mark.asyncio
    async def test_reactivates_deactivated_user(self, db_session: AsyncSession) -> None:
        await _seed_roles(db_session)
        await seed_test_user(
            db_session, email="qa@example.com", password="pw-bbbbbbbb", role_name="reader"
        )
        user = await _user_by_email(db_session, "qa@example.com")
        assert user is not None
        user.is_active = False
        await db_session.commit()

        result = await seed_test_user(
            db_session, email="qa@example.com", password="pw-bbbbbbbb", role_name="reader"
        )
        assert result.status == "updated"
        refreshed = await _user_by_email(db_session, "qa@example.com")
        assert refreshed is not None and refreshed.is_active is True

    @pytest.mark.asyncio
    async def test_refuses_admin_role(self, db_session: AsyncSession) -> None:
        await _seed_roles(db_session)
        with pytest.raises(BootstrapError, match="admin"):
            await seed_test_user(
                db_session, email="qa@example.com", password="pw-cccccccc", role_name="admin"
            )
        # No account leaked from the refused call.
        assert await _user_by_email(db_session, "qa@example.com") is None

    @pytest.mark.asyncio
    async def test_raises_when_role_missing(self, db_session: AsyncSession) -> None:
        # roles table empty → unmigrated DB
        with pytest.raises(BootstrapError, match="reader"):
            await seed_test_user(
                db_session, email="qa@example.com", password="pw-dddddddd", role_name="reader"
            )


class TestResolversAndMain:
    def test_resolve_email_prefers_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_USER_EMAIL", "env@example.com")
        assert _resolve_email("flag@example.com") == "flag@example.com"
        assert _resolve_email(None) == "env@example.com"

    def test_resolve_password_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEST_USER_PASSWORD", raising=False)
        assert _resolve_password(None) is None
        monkeypatch.setenv("TEST_USER_PASSWORD", "from-env")
        assert _resolve_password(None) == "from-env"

    def test_main_noop_without_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEST_USER_EMAIL", raising=False)
        monkeypatch.delenv("TEST_USER_PASSWORD", raising=False)
        # No DB touched, no crash — benign no-op exit 0.
        assert main([]) == 0
