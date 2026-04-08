"""Auth schemas for JWT token and OAuth endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --- JWT Token Schemas ---


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


# --- OAuth Schemas ---


class OAuthLoginResponse(BaseModel):
    """Response for OAuth login initiation — returns the authorization URL."""

    model_config = ConfigDict(frozen=True)

    authorization_url: str
    state: str
    code_verifier: str


class OAuthCallbackRequest(BaseModel):
    """Request body for OAuth callback."""

    model_config = ConfigDict(frozen=True)

    code: str
    state: str
    code_verifier: str


class OAuthUserInfo(BaseModel):
    """Normalized user info extracted from an OAuth provider."""

    model_config = ConfigDict(frozen=True)

    provider: str
    provider_account_id: str
    email: str | None = None
    display_name: str | None = None
    avatar_url: str | None = None


class OAuthCallbackResponse(BaseModel):
    """Response for OAuth callback — returns user data."""

    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    email: str
    display_name: str | None = None
    avatar_url: str | None = None
    is_new_user: bool
    provider: str
    created_at: datetime
