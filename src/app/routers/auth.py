"""Auth routes — JWT token endpoints and OAuth login/callback.

OAuth flow (server-side, post #66):
  1. Frontend hits GET /auth/oauth/{provider}/login — backend stashes state +
     code_verifier in Redis (keyed by state) and returns the authorization_url.
  2. Frontend redirects the browser to authorization_url.
  3. Provider redirects the browser to GET /auth/oauth/{provider}/callback?code=..&state=..
  4. Backend validates state, exchanges code, upserts user, mints tokens, sets the
     refresh_token as an httpOnly cookie, and redirects the browser to
     AUTH_OAUTH_POST_LOGIN_URL with ?token=<access>&is_new_user=0|1 on success,
     or ?error=<code> on failure.
"""

from __future__ import annotations

import json
import secrets
import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from jose.exceptions import JWTError
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings, get_settings
from src.app.database import get_db_session, get_redis
from src.app.models.user import User
from src.app.schemas.auth import (
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
RedisDep = Annotated[Redis, Depends(get_redis)]

AUTH_CODE_PREFIX = "auth_code:"
AUTH_CODE_TTL_SECONDS = 60

# Redis key prefix for in-flight OAuth state (CSRF + PKCE verifier)
OAUTH_STATE_PREFIX = "oauth_state:"

# Error codes emitted in the post-login redirect URL. Kept in sync with
# isnad-graph frontend AuthCallbackPage.tsx ERROR_MESSAGES.
OAUTH_ERROR_INVALID_STATE = "invalid_state"
OAUTH_ERROR_EXCHANGE_FAILED = "oauth_exchange_failed"
OAUTH_ERROR_USER_INFO_FAILED = "oauth_exchange_failed"
OAUTH_ERROR_EMAIL_MISMATCH = "email_mismatch"
OAUTH_ERROR_PROVIDER_DENIED = "provider_denied"
OAUTH_ERROR_UNSUPPORTED_PROVIDER = "unsupported_provider"

VALID_PROVIDERS = {p.value for p in OAuthProvider}


# --- JWT Token Endpoints ---


@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def issue_token(
    body: TokenRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
) -> TokenResponse:
    """Issue an access + refresh token pair after OAuth success.

    Requires a one-time authorization code issued by the OAuth callback endpoint.
    The code is single-use and expires after 60 seconds.
    """
    redis_key = f"{AUTH_CODE_PREFIX}{body.authorization_code}"
    raw = await redis.getdel(redis_key)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authorization code",
        )

    auth_data: dict[str, str | list[str]] = json.loads(raw)
    user_id = uuid.UUID(str(auth_data["user_id"]))
    email = str(auth_data["email"])
    roles: list[str] = auth_data.get("roles", [])  # type: ignore[assignment]
    subscription_status = str(auth_data.get("subscription_status", "free"))

    access_token, expires_at = create_access_token(
        settings=settings,
        user_id=user_id,
        email=email,
        roles=roles,
        subscription_status=subscription_status,
    )
    refresh_token = create_refresh_token()
    await store_refresh_token(
        db=db,
        user_id=user_id,
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


def _build_error_redirect(settings: Settings, error_code: str) -> RedirectResponse:
    """Build a RedirectResponse to the frontend post-login URL with an error param."""
    base = settings.AUTH_OAUTH_POST_LOGIN_URL or "/"
    separator = "&" if "?" in base else "?"
    url = f"{base}{separator}error={urllib.parse.quote(error_code)}"
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/oauth/{provider}/login", response_model=OAuthLoginResponse)
async def oauth_login(
    provider: str,
    settings: SettingsDep,
    redis: RedisDep,
) -> OAuthLoginResponse:
    """Generate an authorization URL with PKCE for the given provider.

    The state and code_verifier are stored in Redis (keyed by state) for the
    server-side callback handler to retrieve. Returning them to the client is
    kept for backwards compatibility with earlier SPA integrations but is no
    longer required for the GET callback flow.
    """
    if provider not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()
    redirect_uri = f"{settings.AUTH_OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"

    # Stash state + code_verifier + provider so the GET callback can verify and exchange.
    await redis.setex(
        f"{OAUTH_STATE_PREFIX}{state}",
        settings.AUTH_OAUTH_STATE_TTL_SECONDS,
        json.dumps({"provider": provider, "code_verifier": code_verifier}),
    )

    oauth = get_oauth_provider(provider, settings)
    authorization_url = oauth.get_authorization_url(state, code_challenge, redirect_uri)

    return OAuthLoginResponse(
        authorization_url=authorization_url,
        state=state,
        code_verifier=code_verifier,
    )


@router.get("/oauth/{provider}/callback", response_class=RedirectResponse)
async def oauth_callback_get(
    provider: str,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    """Server-side OAuth callback — handles the provider's GET redirect.

    This is the endpoint OAuth providers (Google, GitHub, Apple, Facebook) redirect
    the user's browser to after consent. It:
      1. Validates state (CSRF) against Redis, retrieves the stored code_verifier.
      2. Exchanges the authorization code for provider tokens.
      3. Resolves user info and finds-or-creates the local user.
      4. Mints an access token + refresh token, sets the refresh token as an
         httpOnly cookie, and redirects the browser to AUTH_OAUTH_POST_LOGIN_URL
         with the access token on a query param (matching the frontend
         AuthCallbackPage contract).

    On any error, redirects to AUTH_OAUTH_POST_LOGIN_URL with ?error=<code>. We
    use browser redirects for every exit path because this URL is hit by the
    user's browser, not by JS — a JSON error response would be a dead end.

    Issue: noorinalabs/noorinalabs-user-service#66.
    """
    # Provider-denied consent (e.g. "access_denied") → bounce to frontend with error
    if error:
        return _build_error_redirect(settings, OAUTH_ERROR_PROVIDER_DENIED)

    if provider not in VALID_PROVIDERS:
        return _build_error_redirect(settings, OAUTH_ERROR_UNSUPPORTED_PROVIDER)

    if not code or not state:
        return _build_error_redirect(settings, OAUTH_ERROR_INVALID_STATE)

    # Validate state (CSRF) and fetch the PKCE code_verifier. getdel() ensures the
    # state is consumed exactly once — replay of the same callback URL is blocked.
    state_key = f"{OAUTH_STATE_PREFIX}{state}"
    raw_state = await redis.getdel(state_key)
    if raw_state is None:
        return _build_error_redirect(settings, OAUTH_ERROR_INVALID_STATE)

    state_data: dict[str, str] = json.loads(raw_state)
    # Defense in depth: the state entry is keyed by provider at create time; if the
    # user tampered with the `{provider}` path segment, refuse.
    if state_data.get("provider") != provider:
        return _build_error_redirect(settings, OAUTH_ERROR_INVALID_STATE)
    code_verifier = state_data["code_verifier"]

    redirect_uri = f"{settings.AUTH_OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"
    oauth = get_oauth_provider(provider, settings)

    # Exchange code → provider tokens. Provider failures (network, 4xx, malformed
    # response) must bounce the user back with a readable error, not leak as 500.
    try:
        tokens = await oauth.exchange_code(code, code_verifier, redirect_uri)
    except Exception:
        return _build_error_redirect(settings, OAUTH_ERROR_EXCHANGE_FAILED)

    # Fetch user info. Apple returns identity in the id_token; others use access_token.
    if provider == "apple":
        token_for_user_info: str = tokens.get("id_token", "")
    else:
        token_for_user_info = tokens.get("access_token", "")

    try:
        user_info = await oauth.get_user_info(token_for_user_info)
    except Exception:
        return _build_error_redirect(settings, OAUTH_ERROR_USER_INFO_FAILED)

    # Find-or-create user, link OAuth account
    try:
        result = await find_or_create_oauth_user(
            db,
            provider=user_info.provider,
            provider_account_id=user_info.provider_account_id,
            email=user_info.email,
            display_name=user_info.display_name,
            avatar_url=user_info.avatar_url,
        )
    except ValueError:
        # Missing email / email-mismatch-style errors bounce the user back with a
        # readable error code the frontend can render.
        return _build_error_redirect(settings, OAUTH_ERROR_EMAIL_MISMATCH)

    # Collect roles + subscription for the access-token claims
    roles_result = await db.execute(
        text(
            "SELECT r.name FROM roles r "
            "JOIN user_roles ur ON ur.role_id = r.id "
            "WHERE ur.user_id = :uid"
        ),
        {"uid": result.user.id},
    )
    roles = [row[0] for row in roles_result.fetchall()]
    subscription_status = await get_subscription_status(db, result.user.id)

    # Mint tokens directly (no intermediate one-time code — the browser round-trip
    # via redirect is already the single-use handoff). The access token goes on the
    # redirect URL (the frontend AuthCallbackPage stores it in localStorage); the
    # refresh token goes in an httpOnly cookie so JS cannot read it.
    access_token, _ = create_access_token(
        settings=settings,
        user_id=result.user.id,
        email=result.user.email,
        roles=roles,
        subscription_status=subscription_status,
    )
    refresh_token = create_refresh_token()
    await store_refresh_token(
        db=db,
        user_id=result.user.id,
        refresh_token=refresh_token,
        expires_days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    # Build the success redirect with the access token and new-user flag.
    post_login_base = settings.AUTH_OAUTH_POST_LOGIN_URL or "/"
    separator = "&" if "?" in post_login_base else "?"
    params = urllib.parse.urlencode(
        {
            "token": access_token,
            "is_new_user": "1" if result.is_new_user else "0",
            # OAuth users are created with email_verified=True, so verification is
            # never needed via this flow — but we emit the flag for frontend parity.
            "needs_verification": "0",
        }
    )
    redirect_url = f"{post_login_base}{separator}{params}"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)

    # Refresh-token cookie: httpOnly + SameSite=Lax (Lax is required so the cookie
    # survives the cross-site redirect from the OAuth provider back to us; Strict
    # would drop it on the first hop). Secure flag is env-gated for local HTTP dev.
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        httponly=True,
        secure=settings.AUTH_OAUTH_REFRESH_COOKIE_SECURE,
        samesite="lax",
        path="/auth",
    )
    return response
