import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.app.models.role import Role, UserRole
from src.app.models.user import User

ROLE_HIERARCHY: dict[str, int] = {
    "admin": 40,
    "researcher": 30,
    "reader": 20,
    "trial": 10,
}


def get_role_level(role_name: str) -> int:
    return ROLE_HIERARCHY.get(role_name, 0)


def user_has_minimum_role(user_roles: list[str], required_role: str) -> bool:
    required_level = get_role_level(required_role)
    return any(get_role_level(r) >= required_level for r in user_roles)


async def get_user_role_names(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    result = await db.execute(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return list(result.scalars().all())


async def get_all_roles(db: AsyncSession) -> list[Role]:
    result = await db.execute(select(Role).order_by(Role.name))
    return list(result.scalars().all())


async def assign_role(
    db: AsyncSession,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    granted_by: uuid.UUID,
) -> UserRole:
    user_role = UserRole(user_id=user_id, role_id=role_id, granted_by=granted_by)
    db.add(user_role)
    await db.flush()
    # Reload with joined role
    result = await db.execute(
        select(UserRole)
        .options(joinedload(UserRole.role))
        .where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    return result.scalar_one()


async def remove_role(
    db: AsyncSession,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
) -> bool:
    result = await db.execute(
        select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
    )
    user_role = result.scalar_one_or_none()
    if user_role is None:
        return False
    await db.delete(user_role)
    await db.flush()
    return True


async def get_user_roles(db: AsyncSession, user_id: uuid.UUID) -> list[UserRole]:
    result = await db.execute(
        select(UserRole).options(joinedload(UserRole.role)).where(UserRole.user_id == user_id)
    )
    return list(result.unique().scalars().all())


async def load_user_with_roles(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(
        select(User)
        .options(joinedload(User.user_roles).joinedload(UserRole.role))
        .where(User.id == user_id, User.is_active.is_(True))
    )
    return result.unique().scalar_one_or_none()
