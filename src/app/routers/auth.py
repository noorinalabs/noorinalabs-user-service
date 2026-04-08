"""Auth routes — JWT token endpoints and OAuth login/callback."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from jose.exceptions import JWTError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.models.user import User
from src.app.schemas.auth import (
    OAuthCallbackRequest,
    OAuthCallbackResponse,
    OAuthLoginResponse,
    RefreshRequest,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
    TokenValidationResponse,
)
from src.app.services.oauth import OAuthProvider, generate_pkce_pair, get_oauth_provider
from src.app.services.subscription import get_subscription_status
from src.app.services.token import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    revoke_refresh_token,
    store_refresh_token,
    validate_refresh_token,
)
from src.app.services.user import find_or_create_oauth_user

router = APIRouter(prefix="/auth", tags=["auth"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db_session)]

VALID_PROVIDERS = {p.value for p in OAuthProvider}


# --- JWT Token Endpoints ---


@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def issue_token(
    body: TokenRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
) -> TokenResponse:
    """Issue an access + refresh token pair after OAuth success."""
    access_token, expires_at = create_access_token(
        settings=settings,
        user_id=body.user_id,
        email=body.email,
        roles=body.roles,
        subscription_status=body.subscription_status,
    )
    refresh_token = create_refresh_token()
    await store_refresh_token(
        db=db,
        user_id=body.user_id,
        refresh_token=refresh_token,
        expires_days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    expires_in = int((expires_at - datetime.now(UTC)).total_seconds())
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )


@router.post("/token/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def refresh_token(
    body: RefreshRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
) -> TokenResponse:
    """Exchange a refresh token for a new access token (with rotation)."""
    session = await validate_refresh_token(db, body.refresh_token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Rotate: revoke old, issue new
    await revoke_refresh_token(db, body.refresh_token)

    user_result = await db.execute(select(User).where(User.id == session.user_id))
    user = user_result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    roles_result = await db.execute(
        text(
            "SELECT r.name FROM roles r "
            "JOIN user_roles ur ON ur.role_id = r.id "
            "WHERE ur.user_id = :uid"
        ),
        {"uid": session.user_id},
    )
    roles = [row[0] for row in roles_result.fetchall()]

    subscription_status = await get_subscription_status(db, session.user_id)

    access_token, expires_at = create_access_token(
        settings=settings,
        user_id=session.user_id,
        email=user.email,
        roles=roles,
        subscription_status=subscription_status,
    )
    new_refresh = create_refresh_token()
    await store_refresh_token(
        db=db,
        user_id=session.user_id,
        refresh_token=new_refresh,
        expires_days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    expires_in = int((expires_at - datetime.now(UTC)).total_seconds())
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=expires_in,
    )


@router.post("/token/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(body: RevokeRequest, db: DbDep) -> None:
    """Revoke a refresh token (logout)."""
    revoked = await revoke_refresh_token(db, body.refresh_token)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token not found or already revoked",
        )


@router.get("/token/validate", response_model=TokenValidationResponse)
async def validate_token(
    settings: SettingsDep,
    authorization: Annotated[str, Header()],
) -> TokenValidationResponse:
    """Validate an access token (for cross-service calls)."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return TokenValidationResponse(valid=False)

    try:
        payload = decode_access_token(settings, token)
    except JWTError:
        return TokenValidationResponse(valid=False)

    exp = payload.get("exp")
    expires_at = datetime.fromtimestamp(exp, tz=UTC) if exp else None

    return TokenValidationResponse(
        valid=True,
        user_id=uuid.UUID(payload["sub"]),
        email=payload.get("email"),
        roles=payload.get("roles", []),
        subscription_status=payload.get("subscription_status"),
        expires_at=expires_at,
    )


# --- OAuth Endpoints ---


@router.get("/oauth/{provider}/login", response_model=OAuthLoginResponse)
async def oauth_login(provider: str, settings: SettingsDep) -> OAuthLoginResponse:
    """Generate an authorization URL with PKCE for the given provider."""
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    redirect_uri = f"{settings.AUTH_OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"

    oauth = get_oauth_provider(provider, settings)
    authorization_url = oauth.get_authorization_url(state, code_challenge, redirect_uri)

    return OAuthLoginResponse(
        authorization_url=authorization_url,
        state=state,
        code_verifier=code_verifier,
    )


@router.post("/oauth/{provider}/callback", response_model=OAuthCallbackResponse)
async def oauth_callback(
    provider: str,
    body: OAuthCallbackRequest,
    settings: SettingsDep,
    db: AsyncSession = Depends(get_db_session),  # noqa: B008
) -> OAuthCallbackResponse:
    """Handle the OAuth callback — exchange code, find/create user, return user data."""
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    redirect_uri = f"{settings.AUTH_OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"
    oauth = get_oauth_provider(provider, settings)

    # Exchange authorization code for tokens
    try:
        tokens = await oauth.exchange_code(body.code, body.code_verifier, redirect_uri)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Failed to exchange authorization code with the provider",
        ) from exc

    # For Apple, user info is in id_token; for others, use access_token
    if provider == "apple":
        token_for_user_info: str = tokens.get("id_token", "")
    else:
        token_for_user_info = tokens["access_token"]

    try:
        user_info = await oauth.get_user_info(token_for_user_info)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve user info from the provider",
        ) from exc

    # Find or create user, link OAuth account
    try:
        result = await find_or_create_oauth_user(
            db,
            provider=user_info.provider,
            provider_account_id=user_info.provider_account_id,
            email=user_info.email,
            display_name=user_info.display_name,
            avatar_url=user_info.avatar_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return OAuthCallbackResponse(
        user_id=result.user.id,
        email=result.user.email,
        display_name=result.user.display_name,
        avatar_url=result.user.avatar_url,
        is_new_user=result.is_new_user,
        provider=provider,
        created_at=result.user.created_at,
    )
