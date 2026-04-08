"""Unit tests for session lifecycle — create, list, revoke, limits, activity tracking."""

import uuid
from datetime import UTC, datetime
from types import TracebackType

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.models.session import Session
from src.app.models.user import Base, User
from src.app.services.session import (
    MAX_SESSIONS_PER_USER,
    REDIS_SESSION_PREFIX,
    create_session,
    is_session_active,
    list_user_sessions,
    revoke_all_sessions,
    revoke_session,
    update_session_activity,
)
from src.app.services.token import create_refresh_token


def _hash_token(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture
async def db_session() -> AsyncSession:  # type: ignore[misc]
    """Create an in-memory SQLite async session for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session  # type: ignore[misc]
    await engine.dispose()


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        email="test@example.com",
        display_name="Test User",
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    return user


class FakeRedisPipeline:
    """Minimal fake pipeline supporting async context manager and the ops we use."""

    def __init__(self, store: dict[str, object]) -> None:
        self._store = store

    async def __aenter__(self) -> "FakeRedisPipeline":
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
    """In-memory Redis fake supporting the operations used by session service."""

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


class TestCreateSession:
    async def test_creates_session_in_db_and_redis(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        token = create_refresh_token()
        token_hash = _hash_token(token)
        session = await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=token_hash,
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        assert session.id is not None
        assert session.user_id == test_user.id
        assert session.token_hash == token_hash
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "TestBrowser/1.0"
        # SQLite returns naive datetimes; compare without tz
        assert session.expires_at.replace(tzinfo=None) > datetime.now(UTC).replace(tzinfo=None)

        # Verify Redis entry
        redis_key = f"{REDIS_SESSION_PREFIX}{session.id}"
        assert await fake_redis.exists(redis_key) == 1
        stored_user_id = await fake_redis.hget(redis_key, "user_id")
        assert stored_user_id is not None
        assert stored_user_id.decode() == str(test_user.id)

    async def test_evicts_oldest_when_limit_reached(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        session_ids: list[uuid.UUID] = []

        # Create MAX_SESSIONS_PER_USER sessions
        for i in range(MAX_SESSIONS_PER_USER):
            token = create_refresh_token()
            s = await create_session(
                db=db_session,
                redis=fake_redis,  # type: ignore[arg-type]
                user_id=test_user.id,
                token_hash=_hash_token(token),
                ip_address=f"10.0.0.{i}",
            )
            session_ids.append(s.id)

        # Create one more — oldest should be evicted
        extra_token = create_refresh_token()
        await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(extra_token),
        )

        # Check oldest session is revoked
        from sqlalchemy import select

        result = await db_session.execute(
            select(Session).where(Session.id == session_ids[0])
        )
        oldest = result.scalar_one()
        assert oldest.revoked_at is not None


class TestListSessions:
    async def test_lists_active_sessions_only(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        for _ in range(2):
            token = create_refresh_token()
            await create_session(
                db=db_session,
                redis=fake_redis,  # type: ignore[arg-type]
                user_id=test_user.id,
                token_hash=_hash_token(token),
            )

        sessions = await list_user_sessions(
            db=db_session, redis=fake_redis, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert len(sessions) == 2

    async def test_excludes_revoked_sessions(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        token1 = create_refresh_token()
        s1 = await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(token1),
        )

        token2 = create_refresh_token()
        await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(token2),
        )

        await revoke_session(
            db=db_session, redis=fake_redis, session_id=s1.id, user_id=test_user.id  # type: ignore[arg-type]
        )

        sessions = await list_user_sessions(
            db=db_session, redis=fake_redis, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert len(sessions) == 1

    async def test_marks_current_session(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        token = create_refresh_token()
        s = await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(token),
        )

        sessions = await list_user_sessions(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            current_session_id=s.id,
        )
        assert len(sessions) == 1
        assert sessions[0]["is_current"] is True


class TestRevokeSession:
    async def test_revokes_session_in_db_and_redis(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        token = create_refresh_token()
        s = await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(token),
        )

        revoked = await revoke_session(
            db=db_session, redis=fake_redis, session_id=s.id, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert revoked is True

        # DB check
        from sqlalchemy import select

        result = await db_session.execute(select(Session).where(Session.id == s.id))
        db_session_row = result.scalar_one()
        assert db_session_row.revoked_at is not None

        # Redis check
        redis_key = f"{REDIS_SESSION_PREFIX}{s.id}"
        assert await fake_redis.exists(redis_key) == 0

    async def test_returns_false_for_nonexistent_session(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        revoked = await revoke_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            session_id=uuid.uuid4(),
            user_id=test_user.id,
        )
        assert revoked is False

    async def test_cannot_revoke_other_users_session(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        token = create_refresh_token()
        s = await create_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            token_hash=_hash_token(token),
        )

        other_user_id = uuid.uuid4()
        revoked = await revoke_session(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            session_id=s.id,
            user_id=other_user_id,
        )
        assert revoked is False


class TestRevokeAllSessions:
    async def test_revokes_all_sessions(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        for _ in range(3):
            token = create_refresh_token()
            await create_session(
                db=db_session,
                redis=fake_redis,  # type: ignore[arg-type]
                user_id=test_user.id,
                token_hash=_hash_token(token),
            )

        count = await revoke_all_sessions(
            db=db_session, redis=fake_redis, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert count == 3

        sessions = await list_user_sessions(
            db=db_session, redis=fake_redis, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert len(sessions) == 0

    async def test_revokes_all_except_excluded(
        self, db_session: AsyncSession, test_user: User, fake_redis: FakeRedis
    ) -> None:
        session_ids: list[uuid.UUID] = []
        for _ in range(3):
            token = create_refresh_token()
            s = await create_session(
                db=db_session,
                redis=fake_redis,  # type: ignore[arg-type]
                user_id=test_user.id,
                token_hash=_hash_token(token),
            )
            session_ids.append(s.id)

        count = await revoke_all_sessions(
            db=db_session,
            redis=fake_redis,  # type: ignore[arg-type]
            user_id=test_user.id,
            exclude_session_id=session_ids[2],
        )
        assert count == 2

        sessions = await list_user_sessions(
            db=db_session, redis=fake_redis, user_id=test_user.id  # type: ignore[arg-type]
        )
        assert len(sessions) == 1
        assert sessions[0]["id"] == session_ids[2]


class TestSessionActivity:
    async def test_update_last_active(self, fake_redis: FakeRedis) -> None:
        session_id = uuid.uuid4()
        redis_key = f"{REDIS_SESSION_PREFIX}{session_id}"

        # Pre-populate session in Redis
        await fake_redis.hset(redis_key, "last_active", "2026-01-01T00:00:00+00:00")

        await update_session_activity(
            redis=fake_redis, session_id=session_id  # type: ignore[arg-type]
        )

        raw = await fake_redis.hget(redis_key, "last_active")
        assert raw is not None
        updated = datetime.fromisoformat(raw.decode())
        assert updated.year == datetime.now(UTC).year

    async def test_is_session_active_true(self, fake_redis: FakeRedis) -> None:
        session_id = uuid.uuid4()
        redis_key = f"{REDIS_SESSION_PREFIX}{session_id}"
        await fake_redis.hset(redis_key, "user_id", "fake")

        assert await is_session_active(
            redis=fake_redis, session_id=session_id  # type: ignore[arg-type]
        )

    async def test_is_session_active_false(self, fake_redis: FakeRedis) -> None:
        assert not await is_session_active(
            redis=fake_redis, session_id=uuid.uuid4()  # type: ignore[arg-type]
        )
