"""Tests for User CRUD API and role management endpoints."""

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import Settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User

TEST_SECRET = "test-jwt-secret-key"
TEST_ALGORITHM = "HS256"


def _make_token(
    user_id: uuid.UUID,
    roles: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    exp = datetime.now(UTC) + (expires_delta or timedelta(hours=1))
    payload = {"sub": str(user_id), "exp": exp}
    if roles:
        payload["roles"] = roles  # type: ignore[assignment]
    return jwt.encode(payload, TEST_SECRET, algorithm=TEST_ALGORITHM)


@pytest.fixture
async def db_engine():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    # SQLite doesn't enforce foreign keys by default
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


@pytest.fixture
async def seed_roles(db_session: AsyncSession) -> dict[str, Role]:
    roles = {}
    for name, desc in [
        ("admin", "Full platform administration access"),
        ("researcher", "Access to research tools and datasets"),
        ("reader", "Read-only access to public content"),
        ("trial", "Time-limited trial access"),
    ]:
        role = Role(name=name, description=desc)
        db_session.add(role)
        roles[name] = role
    await db_session.commit()
    return roles


@pytest.fixture
async def admin_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(
        email="admin@test.com",
        display_name="Admin User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=seed_roles["admin"].id,
        granted_by=user.id,
    )
    db_session.add(user_role)
    await db_session.commit()
    return user


@pytest.fixture
async def regular_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(
        email="reader@test.com",
        display_name="Regular User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=seed_roles["reader"].id,
    )
    db_session.add(user_role)
    await db_session.commit()
    return user


@pytest.fixture
async def client(
    db_engine,  # type: ignore[no-untyped-def]
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    # Override settings
    def _override_settings() -> Settings:
        return Settings(
            JWT_SECRET=TEST_SECRET,
            JWT_ALGORITHM=TEST_ALGORITHM,
            JWT_PUBLIC_KEY=None,
            DATABASE_URL="sqlite+aiosqlite://",
        )

    # Override db session to use our test session
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    from src.app.config import get_settings

    app.dependency_overrides[get_settings] = _override_settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _auth_header(user: User) -> dict[str, str]:
    token = _make_token(user.id)
    return {"Authorization": f"Bearer {token}"}


class TestGetMe:
    @pytest.mark.asyncio
    async def test_returns_current_user(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get("/api/v1/users/me", headers=_auth_header(regular_user))
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "reader@test.com"
        assert data["display_name"] == "Regular User"

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/users/me")
        assert resp.status_code in (401, 422)


class TestPatchMe:
    @pytest.mark.asyncio
    async def test_update_display_name(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.patch(
            "/api/v1/users/me",
            headers=_auth_header(regular_user),
            json={"display_name": "New Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "New Name"

    @pytest.mark.asyncio
    async def test_update_avatar_url(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.patch(
            "/api/v1/users/me",
            headers=_auth_header(regular_user),
            json={"avatar_url": "https://example.com/avatar.png"},
        )
        assert resp.status_code == 200
        assert resp.json()["avatar_url"] == "https://example.com/avatar.png"


class TestGetUserById:
    @pytest.mark.asyncio
    async def test_admin_can_get_user(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.get(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "reader@test.com"

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_not_found(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{uuid.uuid4()}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 404


class TestListUsers:
    @pytest.mark.asyncio
    async def test_admin_can_list(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.get("/api/v1/users", headers=_auth_header(admin_user))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 2

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get("/api/v1/users", headers=_auth_header(regular_user))
        assert resp.status_code == 403


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_admin_soft_deletes(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 403


class TestRoleEndpoints:
    @pytest.mark.asyncio
    async def test_list_roles(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get("/api/v1/roles", headers=_auth_header(admin_user))
        assert resp.status_code == 200
        names = {r["name"] for r in resp.json()}
        assert "admin" in names
        assert "researcher" in names

    @pytest.mark.asyncio
    async def test_get_user_roles(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get(
            f"/api/v1/users/{admin_user.id}/roles",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 200
        names = [r["name"] for r in resp.json()]
        assert "admin" in names

    @pytest.mark.asyncio
    async def test_assign_and_remove_role(
        self,
        client: AsyncClient,
        admin_user: User,
        regular_user: User,
        seed_roles: dict[str, Role],
    ) -> None:
        researcher_role_id = str(seed_roles["researcher"].id)

        # Assign researcher role
        resp = await client.post(
            f"/api/v1/users/{regular_user.id}/roles",
            headers=_auth_header(admin_user),
            json={"role_id": researcher_role_id},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "researcher"

        # Remove researcher role
        resp = await client.delete(
            f"/api/v1/users/{regular_user.id}/roles/{researcher_role_id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_assign_role_non_admin_forbidden(
        self,
        client: AsyncClient,
        regular_user: User,
        seed_roles: dict[str, Role],
    ) -> None:
        resp = await client.post(
            f"/api/v1/users/{regular_user.id}/roles",
            headers=_auth_header(regular_user),
            json={"role_id": str(seed_roles["researcher"].id)},
        )
        assert resp.status_code == 403
