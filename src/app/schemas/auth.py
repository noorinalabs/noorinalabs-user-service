"""Auth request/response schemas for JWT token endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class TokenRequest(BaseModel):
    """Request body for token issuance after OAuth success."""

    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    email: EmailStr
    roles: list[str] = Field(default_factory=list)
    subscription_status: str = "free"


class TokenResponse(BaseModel):
    """Response containing access and refresh tokens."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    """Request body for token refresh."""

    model_config = ConfigDict(frozen=True)

    refresh_token: str


class RevokeRequest(BaseModel):
    """Request body for token revocation."""

    model_config = ConfigDict(frozen=True)

    refresh_token: str


class TokenValidationResponse(BaseModel):
    """Response for token validation."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    user_id: uuid.UUID | None = None
    email: str | None = None
    roles: list[str] = Field(default_factory=list)
    subscription_status: str | None = None
    expires_at: datetime | None = None


class JWK(BaseModel):
    """JSON Web Key representation."""

    model_config = ConfigDict(frozen=True)

    kty: str
    use: str
    kid: str
    alg: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    """JWKS response containing public keys."""

    model_config = ConfigDict(frozen=True)

    keys: list[JWK]
