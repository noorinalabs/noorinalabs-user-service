"""Tests for the profile preferences API — US #165.

Covers GET/PUT ``/api/v1/users/me/profile``: default empty prefs, round-trip of
known + arbitrary keys, PUT replace semantics, validation (bad theme, oversized
blob), auth gating, and RBAC isolation (a user only ever reads/writes their own
preferences).
"""

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.models.user import Base, User

_test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PRIVATE_PEM = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
TEST_PUBLIC_PEM = (
    _test_private_key.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode()
)


def _make_token(user_id: uuid.UUID) -> str:
    payload = {"sub": str(user_id), "exp": datetime.now(UTC) + timedelta(hours=1)}
    return jwt.encode(payload, TEST_PRIVATE_PEM, algorithm="RS256")


def _auth_header(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_token(user.id)}"}


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
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:  # type: ignore[no-untyped-def]
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


async def _make_user(db_session: AsyncSession, email: str) -> User:
    user = User(email=email, display_name=email, email_verified=True, is_active=True)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture
async def user_a(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "a@test.com")


@pytest.fixture
async def user_b(db_session: AsyncSession) -> User:
    return await _make_user(db_session, "b@test.com")


@pytest.fixture
async def client(
    db_engine,  # type: ignore[no-untyped-def]
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    def _override_settings() -> Settings:
        return Settings(JWT_PUBLIC_KEY=TEST_PUBLIC_PEM, DATABASE_URL="sqlite+aiosqlite://")

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_settings] = _override_settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestGetProfile:
    @pytest.mark.asyncio
    async def test_defaults_to_empty_preferences(self, client: AsyncClient, user_a: User) -> None:
        resp = await client.get("/api/v1/users/me/profile", headers=_auth_header(user_a))
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == str(user_a.id)
        assert body["preferences"] == {}

    @pytest.mark.asyncio
    async def test_unauthenticated_rejected(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/users/me/profile")
        assert resp.status_code in (401, 422)


class TestPutProfile:
    @pytest.mark.asyncio
    async def test_set_and_read_back_known_keys(self, client: AsyncClient, user_a: User) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "dark", "language": "ar"}},
        )
        assert resp.status_code == 200
        assert resp.json()["preferences"] == {"theme": "dark", "language": "ar"}

        # Persisted across requests.
        resp = await client.get("/api/v1/users/me/profile", headers=_auth_header(user_a))
        assert resp.json()["preferences"] == {"theme": "dark", "language": "ar"}

    @pytest.mark.asyncio
    async def test_arbitrary_keys_pass_through(self, client: AsyncClient, user_a: User) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "light", "density": "compact", "beta": True}},
        )
        assert resp.status_code == 200
        assert resp.json()["preferences"] == {
            "theme": "light",
            "density": "compact",
            "beta": True,
        }

    @pytest.mark.asyncio
    async def test_put_replaces_wholesale(self, client: AsyncClient, user_a: User) -> None:
        await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "dark", "language": "en"}},
        )
        # A subsequent PUT with only `theme` drops the previously stored `language`.
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "system"}},
        )
        assert resp.status_code == 200
        assert resp.json()["preferences"] == {"theme": "system"}

    @pytest.mark.asyncio
    async def test_none_valued_known_key_is_dropped(
        self, client: AsyncClient, user_a: User
    ) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": None, "language": "fr"}},
        )
        assert resp.status_code == 200
        assert resp.json()["preferences"] == {"language": "fr"}

    @pytest.mark.asyncio
    async def test_invalid_theme_rejected(self, client: AsyncClient, user_a: User) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "neon"}},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_oversized_preferences_rejected(self, client: AsyncClient, user_a: User) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"blob": "x" * 9000}},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_unauthenticated_rejected(self, client: AsyncClient) -> None:
        resp = await client.put(
            "/api/v1/users/me/profile",
            json={"preferences": {"theme": "dark"}},
        )
        assert resp.status_code in (401, 422)


class TestProfileRbacIsolation:
    @pytest.mark.asyncio
    async def test_users_have_independent_preferences(
        self, client: AsyncClient, user_a: User, user_b: User
    ) -> None:
        # user_a writes their preferences.
        await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_a),
            json={"preferences": {"theme": "dark"}},
        )
        # user_b's profile is unaffected — each token only ever resolves to its
        # own user (no cross-user read/write surface).
        resp_b = await client.get("/api/v1/users/me/profile", headers=_auth_header(user_b))
        assert resp_b.json()["preferences"] == {}

        # user_b writes their own — user_a still sees theirs.
        await client.put(
            "/api/v1/users/me/profile",
            headers=_auth_header(user_b),
            json={"preferences": {"theme": "light"}},
        )
        resp_a = await client.get("/api/v1/users/me/profile", headers=_auth_header(user_a))
        assert resp_a.json()["preferences"] == {"theme": "dark"}
