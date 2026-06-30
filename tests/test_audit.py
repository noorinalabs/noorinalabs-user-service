"""Tests for the relational audit_log table + create/list endpoints (us#200).

The in-memory SQLite suite (always on, fast) exercises the endpoints end-to-end:
create→list round-trip, the ``action`` exact-match filter, pagination bounds,
RBAC (non-admin → 403), and newest-first ordering.

A second module-level class re-proves the REAL Alembic migration (0043) up/down
against a throwaway Postgres container — opt-in and skip-guarded
(``RUN_PG_CONTAINER_TESTS=1``), mirroring ``test_oauth_account_linking_guard_pg``.
The migration uses ``postgresql.UUID`` / ``gen_random_uuid()`` / ``now()`` which
only run on Postgres, so SQLite cannot stand in for it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import Settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.models.audit_log import AuditLog
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User

# Generate a test RSA key pair (once per module)
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
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:  # type: ignore[no-untyped-def, type-arg]
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def seed_roles(db_session: AsyncSession) -> dict[str, Role]:
    roles = {}
    for name, desc in [
        ("admin", "Full platform administration access"),
        ("reader", "Read-only access to public content"),
    ]:
        role = Role(name=name, description=desc)
        db_session.add(role)
        roles[name] = role
    await db_session.commit()
    return roles


@pytest.fixture
async def admin_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(email="admin@test.com", display_name="Admin User", email_verified=True)
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["admin"].id, granted_by=user.id))
    await db_session.commit()
    return user


@pytest.fixture
async def regular_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(email="reader@test.com", display_name="Regular User", email_verified=True)
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["reader"].id))
    await db_session.commit()
    return user


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

    from src.app.config import get_settings

    app.dependency_overrides[get_settings] = _override_settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestCreateAuditEntry:
    @pytest.mark.asyncio
    async def test_admin_creates_and_lists_round_trip(
        self, client: AsyncClient, admin_user: User
    ) -> None:
        target = uuid.uuid4()
        resp = await client.post(
            "/api/v1/audit",
            headers=_auth_header(admin_user),
            json={
                "action": "user.role.granted",
                "actor_id": str(admin_user.id),
                "actor_name": "Admin User",
                "target_user_id": str(target),
                "details": "granted researcher",
            },
        )
        assert resp.status_code == 201
        created = resp.json()
        assert created["action"] == "user.role.granted"
        assert created["actor_id"] == str(admin_user.id)
        assert created["actor_name"] == "Admin User"
        assert created["target_user_id"] == str(target)
        assert created["details"] == "granted researcher"
        assert created["id"]
        assert created["created_at"]

        # Round-trip: the entry shows up in the list.
        listing = await client.get("/api/v1/audit", headers=_auth_header(admin_user))
        assert listing.status_code == 200
        body = listing.json()
        assert body["total"] == 1
        assert body["page"] == 1
        assert body["limit"] == 20
        assert [e["id"] for e in body["items"]] == [created["id"]]

    @pytest.mark.asyncio
    async def test_optional_fields_default_to_empty_and_null(
        self, client: AsyncClient, admin_user: User
    ) -> None:
        resp = await client.post(
            "/api/v1/audit",
            headers=_auth_header(admin_user),
            json={"action": "system.boot", "actor_id": str(admin_user.id)},
        )
        assert resp.status_code == 201
        created = resp.json()
        assert created["actor_name"] == ""
        assert created["details"] == ""
        assert created["target_user_id"] is None

    @pytest.mark.asyncio
    async def test_empty_action_rejected(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.post(
            "/api/v1/audit",
            headers=_auth_header(admin_user),
            json={"action": "", "actor_id": str(admin_user.id)},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.post(
            "/api/v1/audit",
            headers=_auth_header(regular_user),
            json={"action": "x", "actor_id": str(regular_user.id)},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/audit",
            json={"action": "x", "actor_id": str(uuid.uuid4())},
        )
        assert resp.status_code in (401, 422)


async def _seed_entries(db: AsyncSession, specs: list[tuple[str, datetime]]) -> None:
    """Insert audit rows with explicit action + created_at for deterministic order."""
    for action, created in specs:
        db.add(
            AuditLog(
                action=action,
                actor_id=uuid.uuid4(),
                actor_name="seed",
                created_at=created,
            )
        )
    await db.commit()


class TestListAuditEntries:
    @pytest.mark.asyncio
    async def test_action_filter_exact_match(
        self, client: AsyncClient, admin_user: User, db_session: AsyncSession
    ) -> None:
        now = datetime.now(UTC)
        await _seed_entries(
            db_session,
            [
                ("login", now - timedelta(minutes=3)),
                ("logout", now - timedelta(minutes=2)),
                ("login", now - timedelta(minutes=1)),
            ],
        )
        resp = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"action": "login"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert {e["action"] for e in body["items"]} == {"login"}

    @pytest.mark.asyncio
    async def test_pagination_bounds(
        self, client: AsyncClient, admin_user: User, db_session: AsyncSession
    ) -> None:
        now = datetime.now(UTC)
        await _seed_entries(db_session, [(f"a{i}", now - timedelta(minutes=i)) for i in range(5)])
        page1 = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"page": 1, "limit": 2}
        )
        page2 = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"page": 2, "limit": 2}
        )
        page3 = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"page": 3, "limit": 2}
        )
        for resp in (page1, page2, page3):
            assert resp.status_code == 200
            assert resp.json()["total"] == 5
        assert len(page1.json()["items"]) == 2
        assert len(page2.json()["items"]) == 2
        assert len(page3.json()["items"]) == 1
        # No row appears on two pages.
        seen = [e["id"] for p in (page1, page2, page3) for e in p.json()["items"]]
        assert len(seen) == len(set(seen)) == 5

    @pytest.mark.asyncio
    async def test_limit_out_of_range_rejected(self, client: AsyncClient, admin_user: User) -> None:
        too_big = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"limit": 101}
        )
        too_small = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"limit": 0}
        )
        bad_page = await client.get(
            "/api/v1/audit", headers=_auth_header(admin_user), params={"page": 0}
        )
        assert too_big.status_code == 422
        assert too_small.status_code == 422
        assert bad_page.status_code == 422

    @pytest.mark.asyncio
    async def test_ordered_created_at_desc(
        self, client: AsyncClient, admin_user: User, db_session: AsyncSession
    ) -> None:
        now = datetime.now(UTC)
        await _seed_entries(
            db_session,
            [
                ("oldest", now - timedelta(hours=2)),
                ("middle", now - timedelta(hours=1)),
                ("newest", now),
            ],
        )
        resp = await client.get("/api/v1/audit", headers=_auth_header(admin_user))
        assert resp.status_code == 200
        actions = [e["action"] for e in resp.json()["items"]]
        assert actions == ["newest", "middle", "oldest"]

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get("/api/v1/audit", headers=_auth_header(regular_user))
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_unauthenticated_rejected(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/audit")
        assert resp.status_code in (401, 422)


# ---------------------------------------------------------------------------
# Real-Postgres migration up/down proof (opt-in, skip-guarded).
# ---------------------------------------------------------------------------
_PG_TESTS_ENABLED = os.getenv("RUN_PG_CONTAINER_TESTS") == "1"

pg_only = pytest.mark.skipif(
    not _PG_TESTS_ENABLED,
    reason="Postgres container test is opt-in; set RUN_PG_CONTAINER_TESTS=1 to run.",
)

_REPO_ROOT = Path(__file__).resolve().parents[1]


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


def _alembic(target: str, database_url: str) -> None:
    """Run a real `alembic` command (its own process) against ``database_url``.

    Drives the genuine ``alembic/env.py`` online path — exactly what
    ``make migrate`` does in production — so the migration is exercised as
    written, not reimplemented in the test.
    """
    env = {**os.environ, "DATABASE_URL": database_url, "ENVIRONMENT": "test"}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", target]
        if not target.startswith("down:")
        else [sys.executable, "-m", "alembic", "downgrade", target.removeprefix("down:")],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"alembic {target} failed:\n{result.stdout}\n{result.stderr}"


@pg_only
class TestAuditLogMigrationPostgres:
    @pytest.mark.asyncio
    async def test_upgrade_creates_then_downgrade_drops(self, pg_url: str) -> None:
        # upgrade to head (0043) — table + indexes must exist.
        _alembic("head", pg_url)
        engine = create_async_engine(pg_url, echo=False)
        try:
            async with engine.connect() as conn:
                exists = await conn.scalar(text("SELECT to_regclass('public.audit_log')"))
                assert exists == "audit_log"
                index_names = set(
                    (
                        await conn.execute(
                            text("SELECT indexname FROM pg_indexes WHERE tablename = 'audit_log'")
                        )
                    )
                    .scalars()
                    .all()
                )
                assert "ix_audit_log_created_at" in index_names
                assert "ix_audit_log_action" in index_names

            # downgrade one step (back to 0042) — table must be gone.
            _alembic("down:0042", pg_url)
            async with engine.connect() as conn:
                assert await conn.scalar(text("SELECT to_regclass('public.audit_log')")) is None
        finally:
            await engine.dispose()
