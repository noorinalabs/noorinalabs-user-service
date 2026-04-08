from typing import Annotated, Any

from fastapi import APIRouter, Depends

from src.app.config import Settings, get_settings
from src.app.schemas.auth import JWKSResponse
from src.app.services.token import get_jwks

router = APIRouter(tags=["well-known"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
async def jwks_endpoint(settings: SettingsDep) -> dict[str, Any]:
    """JWKS public key endpoint for RS256 verification."""
    return get_jwks(settings)
