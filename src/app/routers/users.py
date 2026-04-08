import uuid

from fastapi import APIRouter, HTTPException, Query, status

from src.app.dependencies import AdminUserDep, CurrentUserDep, DbDep
from src.app.schemas.user import (
    RoleAssignment,
    RoleRead,
    UserListResponse,
    UserRead,
    UserUpdate,
)
from src.app.services import rbac
from src.app.services import user as user_svc

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _user_to_read(u: object) -> UserRead:
    from src.app.models.user import User

    assert isinstance(u, User)
    role_names = [ur.role.name for ur in u.user_roles] if u.user_roles else []
    return UserRead(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        email_verified=u.email_verified,
        avatar_url=u.avatar_url,
        locale=u.locale,
        is_active=u.is_active,
        created_at=u.created_at,
        roles=role_names,
    )


@router.get("/me", response_model=UserRead)
async def get_current_user_profile(current_user: CurrentUserDep) -> UserRead:
    return _user_to_read(current_user)


@router.patch("/me", response_model=UserRead)
async def update_current_user_profile(
    data: UserUpdate,
    current_user: CurrentUserDep,
    db: DbDep,
) -> UserRead:
    updated = await user_svc.update_profile(db, current_user, data)
    await db.commit()
    return _user_to_read(updated)


@router.get("/{user_id}", response_model=UserRead)
async def get_user_by_id(
    user_id: uuid.UUID,
    _admin: AdminUserDep,
    db: DbDep,
) -> UserRead:
    user = await user_svc.get_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _user_to_read(user)


@router.get("", response_model=UserListResponse)
async def list_users(
    _admin: AdminUserDep,
    db: DbDep,
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> UserListResponse:
    users, next_cursor = await user_svc.list_users(db, cursor=cursor, limit=limit)
    return UserListResponse(
        items=[_user_to_read(u) for u in users],
        next_cursor=next_cursor,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    _admin: AdminUserDep,
    db: DbDep,
) -> None:
    user = await user_svc.soft_delete(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await db.commit()


# --- Role management ---


@router.get("/{user_id}/roles", response_model=list[RoleRead])
async def get_user_roles(
    user_id: uuid.UUID,
    _current_user: CurrentUserDep,
    db: DbDep,
) -> list[RoleRead]:
    user_roles = await rbac.get_user_roles(db, user_id)
    return [RoleRead.model_validate(ur.role) for ur in user_roles]


@router.post("/{user_id}/roles", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
async def assign_role_to_user(
    user_id: uuid.UUID,
    body: RoleAssignment,
    admin: AdminUserDep,
    db: DbDep,
) -> RoleRead:
    # Verify target user exists
    target = await user_svc.get_by_id(db, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    try:
        user_role = await rbac.assign_role(db, user_id, body.role_id, granted_by=admin.id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already assigned or role not found",
        ) from exc
    await db.commit()
    return RoleRead.model_validate(user_role.role)


@router.delete(
    "/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_role_from_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    _admin: AdminUserDep,
    db: DbDep,
) -> None:
    removed = await rbac.remove_role(db, user_id, role_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role assignment not found",
        )
    await db.commit()
