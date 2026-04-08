import uuid
from base64 import b64decode, b64encode
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.app.models.role import UserRole
from src.app.models.user import User
from src.app.schemas.user import UserUpdate


async def get_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(
        select(User)
        .options(joinedload(User.user_roles).joinedload(UserRole.role))
        .where(User.id == user_id)
    )
    return result.unique().scalar_one_or_none()


async def update_profile(db: AsyncSession, user: User, data: UserUpdate) -> User:
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    await db.flush()
    await db.refresh(user)
    return user


async def list_users(
    db: AsyncSession,
    cursor: str | None = None,
    limit: int = 20,
) -> tuple[list[User], str | None]:
    query = (
        select(User)
        .options(joinedload(User.user_roles).joinedload(UserRole.role))
        .order_by(User.created_at, User.id)
        .limit(limit + 1)
    )

    if cursor:
        try:
            decoded = b64decode(cursor).decode()
            ts_str, uid_str = decoded.rsplit("|", 1)
            cursor_ts = datetime.fromisoformat(ts_str)
            cursor_id = uuid.UUID(uid_str)
        except (ValueError, UnicodeDecodeError):
            pass
        else:
            query = query.where(
                (User.created_at > cursor_ts)
                | ((User.created_at == cursor_ts) & (User.id > cursor_id))
            )

    result = await db.execute(query)
    users = list(result.unique().scalars().all())

    next_cursor: str | None = None
    if len(users) > limit:
        users = users[:limit]
        last = users[-1]
        raw = f"{last.created_at.isoformat()}|{last.id}"
        next_cursor = b64encode(raw.encode()).decode()

    return users, next_cursor


async def soft_delete(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    user = await get_by_id(db, user_id)
    if user is None:
        return None
    user.is_active = False
    await db.flush()
    await db.refresh(user)
    return user
