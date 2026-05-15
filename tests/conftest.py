"""Shared pytest fixtures for the user-service test suite.

Before US#56 each of test_users_crud.py / test_subscriptions.py /
test_verification.py generated its own RSA key pair, defined its own
`_make_token` / `_auth_header` helpers, and rolled its own
`db_engine` / `db_session` / `seed_roles` / `admin_user` / `regular_user` /
`client` fixture chain — all byte-identical or near-identical. This module
consolidates them so individual test files only declare what is genuinely
specific to them.

The RSA key pair is generated once per test session (module-level constants)
— keygen is the slow part, so sharing it across the whole run matters.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Callable
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any

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
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User

# --- RSA key pair (generated once per test session) ---

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


# --- Token helpers ---


def make_token(
    user_id: uuid.UUID,
    roles: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Sign an RS256 access token for `user_id` with the test private key.

    Mirrors the shape the service issues: `sub`, `exp`, optional `roles`.
    """
    exp = datetime.now(UTC) + (expires_delta or timedelta(hours=1))
    payload: dict[str, Any] = {"sub": str(user_id), "exp": exp}
    if roles:
        payload["roles"] = roles
    return jwt.encode(payload, TEST_PRIVATE_PEM, algorithm="RS256")


def auth_header(user: User, roles: list[str] | None = None) -> dict[str, str]:
    """Return an Authorization header carrying a freshly-signed token for `user`."""
    return {"Authorization": f"Bearer {make_token(user.id, roles=roles)}"}


# --- Redis fake (used by session HTTP + service tests) ---


class FakeRedisPipeline:
    """Minimal fake pipeline supporting async context manager and the ops we use."""

    def __init__(self, store: dict[str, object]) -> None:
        self._store = store

    async def __aenter__(self) -> FakeRedisPipeline:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass

    async def hset(self, key: str, mapping: dict[str, str] | None = None, **kwargs: str) -> int:
        data = mapping or kwargs
        if key not in self._store:
            self._store[key] = {}
        store_hash: dict[str, bytes] = self._store[key]  # type: ignore[assignment]
        for k, v in data.items():
            store_hash[k] = v.encode() if isinstance(v, str) else v  # type: ignore[assignment]
        return len(data)

    async def expire(self, key: str, ttl: int) -> bool:
        return True

    async def sadd(self, key: str, *values: str) -> int:
        if key not in self._store:
            self._store[key] = set()
        store_set: set[str] = self._store[key]  # type: ignore[assignment]
        for v in values:
            store_set.add(str(v))
        return len(values)

    async def srem(self, key: str, *values: str) -> int:
        if key in self._store and isinstance(self._store[key], set):
            store_set: set[str] = self._store[key]  # type: ignore[assignment]
            for v in values:
                store_set.discard(str(v))
        return 1

    async def delete(self, key: str) -> int:
        if key in self._store:
            del self._store[key]
            return 1
        return 0

    async def execute(self) -> list[object]:
        return []


class FakeRedis:
    """In-memory Redis fake supporting the operations used by the session service."""

    def __init__(self) -> None:
        self._store: dict[str, object] = {}

    def pipeline(self) -> FakeRedisPipeline:
        return FakeRedisPipeline(self._store)

    async def hget(self, key: str, field: str) -> bytes | None:
        h = self._store.get(key)
        if isinstance(h, dict):
            return h.get(field)  # type: ignore[return-value]
        return None

    async def hset(self, key: str, field: str, value: str) -> int:
        if key not in self._store:
            self._store[key] = {}
        store_hash: dict[str, bytes] = self._store[key]  # type: ignore[assignment]
        store_hash[field] = value.encode()
        return 1

    async def exists(self, key: str) -> int:
        return 1 if key in self._store else 0

    async def delete(self, key: str) -> int:
        if key in self._store:
            del self._store[key]
            return 1
        return 0


@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()


# --- Database fixtures ---


@pytest.fixture
async def db_engine() -> AsyncGenerator[Any, None]:
    """In-memory SQLite engine with the full schema and FK enforcement on.

    SQLite does not enforce foreign keys by default; the PRAGMA matches the
    behaviour the Postgres-backed prod path gives us.
    """
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn: Any, _connection_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine: Any) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def seed_roles(db_session: AsyncSession) -> dict[str, Role]:
    """Seed the four platform roles and return them keyed by name."""
    roles: dict[str, Role] = {}
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
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["admin"].id, granted_by=user.id))
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
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["reader"].id))
    await db_session.commit()
    return user


# --- Settings + client fixtures ---


def build_test_settings(**overrides: Any) -> Settings:
    """Construct a Settings for tests — RS256 public key wired, SQLite URL.

    `overrides` lets a test file add what it needs (e.g.
    `WEBHOOK_SIGNING_SECRET`) without re-declaring the whole object.
    """
    base: dict[str, Any] = {
        "JWT_PUBLIC_KEY": TEST_PUBLIC_PEM,
        "DATABASE_URL": "sqlite+aiosqlite://",
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings() -> Settings:
    return build_test_settings()


@pytest.fixture
async def client(
    db_engine: Any,
    settings: Settings,
) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client bound to the app with DB + settings dependency overrides.

    Test files that need extra settings (e.g. a webhook secret) override the
    `settings` fixture locally — the `client` fixture picks it up by injection.
    """
    app = create_app()
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def client_factory(db_engine: Any) -> Callable[..., Any]:
    """Factory for a client with caller-supplied settings overrides + redis dep.

    Some suites (session HTTP tests) need a FakeRedis wired into `get_redis`
    and per-test settings; this returns a builder so they don't each rebuild
    the override boilerplate.
    """

    def _make(
        settings_overrides: dict[str, Any] | None = None,
        redis: Any | None = None,
    ) -> AsyncClient:
        from src.app.database import get_redis

        app = create_app()
        test_settings = build_test_settings(**(settings_overrides or {}))
        session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

        async def _override_db() -> AsyncGenerator[AsyncSession, None]:
            async with session_factory() as session:
                yield session

        app.dependency_overrides[get_settings] = lambda: test_settings
        app.dependency_overrides[get_db_session] = _override_db
        if redis is not None:

            async def _override_redis() -> AsyncGenerator[Any, None]:
                yield redis

            app.dependency_overrides[get_redis] = _override_redis

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        return AsyncClient(transport=transport, base_url="http://test", follow_redirects=False)

    return _make
