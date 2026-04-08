from fastapi import APIRouter

from src.app.dependencies import CurrentUserDep, DbDep
from src.app.schemas.user import RoleRead
from src.app.services import rbac

router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


@router.get("", response_model=list[RoleRead])
async def list_roles(
    _current_user: CurrentUserDep,
    db: DbDep,
) -> list[RoleRead]:
    roles = await rbac.get_all_roles(db)
    return [RoleRead.model_validate(r) for r in roles]
