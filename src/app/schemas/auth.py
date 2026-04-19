"""Auth schemas for JWT token and OAuth endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# --- JWT Token Schemas ---


class TokenRequest(BaseModel):
    """Request body for token issuance — requires a one-time auth code from OAuth."""

    model_config = ConfigDict(frozen=True)

    authorization_code: str


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
    """Response for OAuth login initiation — returns the authorization URL.

    `state` and `code_verifier` are retained for backwards compatibility with
    earlier SPA-driven callback flows. As of #66 the server-side GET callback
    reads them from Redis; clients may ignore both fields.
    """

    model_config = ConfigDict(frozen=True)

    authorization_url: str
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
