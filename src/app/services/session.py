"""Session service — US #7.

Redis-backed session management with TTL, per-user limits, and activity tracking.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.models.session import Session

MAX_SESSIONS_PER_USER = 10
SESSION_TTL_DAYS = 30
REDIS_SESSION_PREFIX = "session:"
REDIS_USER_SESSIONS_PREFIX = "user_sessions:"


async def create_session(
    db: AsyncSession,
    redis: Redis,
    user_id: uuid.UUID,
    token_hash: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Session:
    """Create a new session, store in DB and Redis. Evicts oldest if limit reached."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=SESSION_TTL_DAYS)
    ttl_seconds = SESSION_TTL_DAYS * 86400

    # Enforce per-user session limit — evict oldest if at capacity
    await _enforce_session_limit(db, redis, user_id)

    session = Session(
        user_id=user_id,
        token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)

    # Store in Redis with TTL
    redis_key = f"{REDIS_SESSION_PREFIX}{session.id}"
    user_set_key = f"{REDIS_USER_SESSIONS_PREFIX}{user_id}"

    async with redis.pipeline() as pipe:
        await pipe.hset(  # type: ignore[misc]
            redis_key,
            mapping={
                "user_id": str(user_id),
                "session_id": str(session.id),
                "ip_address": ip_address or "",
                "user_agent": user_agent or "",
                "created_at": now.isoformat(),
                "last_active": now.isoformat(),
                "expires_at": expires_at.isoformat(),
            },
        )
        await pipe.expire(redis_key, ttl_seconds)
        await pipe.sadd(user_set_key, str(session.id))  # type: ignore[misc]
        await pipe.expire(user_set_key, ttl_seconds)
        await pipe.execute()

    return session


async def list_user_sessions(
    db: AsyncSession,
    redis: Redis,
    user_id: uuid.UUID,
    current_session_id: uuid.UUID | None = None,
) -> list[dict[str, object]]:
    """List all active (non-revoked, non-expired) sessions for a user."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(Session)
        .where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
            Session.expires_at > now,
        )
        .order_by(Session.last_active.desc())
    )
    sessions = list(result.scalars().all())

    enriched: list[dict[str, object]] = []
    for s in sessions:
        # Try to get last_active from Redis (more up-to-date)
        redis_key = f"{REDIS_SESSION_PREFIX}{s.id}"
        last_active_raw: bytes | None = await redis.hget(redis_key, "last_active")  # type: ignore[misc]
        last_active: datetime = (
            datetime.fromisoformat(last_active_raw.decode()) if last_active_raw else s.last_active
        )
        enriched.append(
            {
                "id": s.id,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at,
                "last_active": last_active,
                "expires_at": s.expires_at,
                "is_current": s.id == current_session_id,
            }
        )
    return enriched


async def revoke_session(
    db: AsyncSession,
    redis: Redis,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
) -> bool:
    """Revoke a specific session. Returns True if a session was revoked."""
    now = datetime.now(UTC)
    cursor_result: CursorResult[Any] = await db.execute(  # type: ignore[assignment]
        update(Session)
        .where(
            Session.id == session_id,
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await db.flush()

    if cursor_result.rowcount == 0:
        return False

    # Remove from Redis
    redis_key = f"{REDIS_SESSION_PREFIX}{session_id}"
    user_set_key = f"{REDIS_USER_SESSIONS_PREFIX}{user_id}"
    async with redis.pipeline() as pipe:
        await pipe.delete(redis_key)
        await pipe.srem(user_set_key, str(session_id))  # type: ignore[misc]
        await pipe.execute()

    return True


async def revoke_all_sessions(
    db: AsyncSession,
    redis: Redis,
    user_id: uuid.UUID,
    exclude_session_id: uuid.UUID | None = None,
) -> int:
    """Revoke all sessions for a user. Optionally exclude one (current session)."""
    now = datetime.now(UTC)

    # Get all active session IDs first for Redis cleanup
    result = await db.execute(
        select(Session.id).where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
        )
    )
    session_ids = [row[0] for row in result.fetchall()]

    if exclude_session_id:
        session_ids = [sid for sid in session_ids if sid != exclude_session_id]

    if not session_ids:
        return 0

    # Revoke in DB
    cursor_result: CursorResult[Any] = await db.execute(  # type: ignore[assignment]
        update(Session)
        .where(
            Session.id.in_(session_ids),
            Session.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await db.flush()
    revoked_count: int = cursor_result.rowcount

    # Clean up Redis
    user_set_key = f"{REDIS_USER_SESSIONS_PREFIX}{user_id}"
    async with redis.pipeline() as pipe:
        for sid in session_ids:
            await pipe.delete(f"{REDIS_SESSION_PREFIX}{sid}")
            await pipe.srem(user_set_key, str(sid))  # type: ignore[misc]
        await pipe.execute()

    return revoked_count


async def update_session_activity(
    redis: Redis,
    session_id: uuid.UUID,
) -> None:
    """Update last_active timestamp in Redis for a session."""
    redis_key = f"{REDIS_SESSION_PREFIX}{session_id}"
    if await redis.exists(redis_key):
        await redis.hset(redis_key, "last_active", datetime.now(UTC).isoformat())  # type: ignore[misc]


async def is_session_active(
    redis: Redis,
    session_id: uuid.UUID,
) -> bool:
    """Check if a session exists in Redis (not expired, not revoked)."""
    redis_key = f"{REDIS_SESSION_PREFIX}{session_id}"
    return bool(await redis.exists(redis_key))


async def _enforce_session_limit(
    db: AsyncSession,
    redis: Redis,
    user_id: uuid.UUID,
) -> None:
    """Evict the oldest session if the user has reached the max session limit."""
    result = await db.execute(
        select(Session)
        .where(
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
            Session.expires_at > datetime.now(UTC),
        )
        .order_by(Session.created_at.asc())
    )
    active_sessions = list(result.scalars().all())

    if len(active_sessions) >= MAX_SESSIONS_PER_USER:
        oldest = active_sessions[0]
        await revoke_session(db, redis, oldest.id, user_id)
