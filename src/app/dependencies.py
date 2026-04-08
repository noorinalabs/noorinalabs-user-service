from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings, get_settings
from src.app.database import get_db_session, get_redis
from src.app.models.user import User
from src.app.services.rbac import get_user_role_names, load_user_with_roles, user_has_minimum_role

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]


async def get_current_user(
    authorization: Annotated[str, Header()],
    db: DbDep,
    settings: SettingsDep,
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )
    token = authorization.removeprefix("Bearer ")

    # RS256 only — no fallback to weaker algorithms
    if not settings.JWT_PUBLIC_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT public key not configured",
        )

    try:
        payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from err

    user_id_str: str | None = payload.get("sub")
    if user_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in token",
        ) from err

    user = await load_user_with_roles(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


async def require_admin(
    user: CurrentUserDep,
    db: DbDep,
) -> User:
    role_names = await get_user_role_names(db, user.id)
    if not user_has_minimum_role(role_names, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


AdminUserDep = Annotated[User, Depends(require_admin)]


def require_role(
    role_name: str,
) -> Callable[..., Coroutine[Any, Any, User]]:
    async def _check(user: CurrentUserDep, db: DbDep) -> User:
        role_names = await get_user_role_names(db, user.id)
        if not user_has_minimum_role(role_names, role_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires at least '{role_name}' role",
            )
        return user

    return _check
