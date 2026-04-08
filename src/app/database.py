"""Async database engine, session management, and Redis connection."""

from collections.abc import AsyncGenerator

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import get_settings

_async_session_factory: async_sessionmaker[AsyncSession] | None = None
_redis_client: Redis | None = None


async def init_db() -> None:
    """Initialize the database engine and session factory."""
    global _async_session_factory
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    _async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def init_redis() -> None:
    """Initialize the Redis client."""
    global _redis_client
    settings = get_settings()
    _redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=False)


async def close_db() -> None:
    """Dispose the engine and clear the session factory."""
    global _async_session_factory
    if _async_session_factory is not None:
        # Get engine from the session factory bind
        engine = _async_session_factory.kw.get("bind")
        if engine is not None:
            await engine.dispose()
    _async_session_factory = None


async def close_redis() -> None:
    """Close the Redis connection."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
    _redis_client = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    assert _async_session_factory is not None, "Database not initialized"
    async with _async_session_factory() as session:
        yield session


async def get_redis() -> AsyncGenerator[Redis, None]:
    """FastAPI dependency that yields the Redis client."""
    assert _redis_client is not None, "Redis not initialized"
    yield _redis_client
