"""Auth routes — JWT token endpoints and OAuth login/callback.

OAuth flow (server-side, post #66):
  1. Frontend hits GET /auth/oauth/{provider}/login — backend stashes state +
     code_verifier in Redis (keyed by state) and returns the authorization_url.
  2. Frontend redirects the browser to authorization_url.
  3. Provider redirects the browser to GET /auth/oauth/{provider}/callback?code=..&state=..
  4. Backend validates state, exchanges code, upserts user, mints tokens, sets the
     refresh_token as an httpOnly cookie, and redirects the browser to
     AUTH_OAUTH_POST_LOGIN_URL. On success the access token is delivered in the
     URL *fragment* (`#token=<access>`) so it never leaks via the Referer header
     (#68), while the non-secret flags stay as query params
     (`?is_new_user=0|1&needs_verification=0`). On failure the redirect carries
     `?error=<code>`.
"""

from __future__ import annotations

import json
import logging
import secrets
import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from jose.exceptions import JWTError
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings, get_settings
from src.app.database import get_db_session, get_redis, get_redis_optional
from src.app.dependencies import get_current_user
from src.app.models.user import User
from src.app.schemas.auth import (
    AuthProviderInfo,
    ForwardAuthResponse,
    LoginRequest,
    OAuthLoginResponse,
    ProvidersResponse,
    RefreshRequest,
    RegisterRequest,
    RevokeRequest,
    SsoCookieResponse,
    TokenRequest,
    TokenResponse,
    TokenValidationResponse,
)
from src.app.services.oauth import (
    OAuthProvider,
    generate_pkce_pair,
    get_oauth_provider,
    is_oauth_provider_configured,
)
from src.app.services.rate_limit import check_rate_limit, enforce_ip_rate_limit
from src.app.services.rbac import get_role_level, get_user_role_names, user_has_minimum_role
from src.app.services.subscription import get_subscription_status
from src.app.services.token import (
    create_access_token,
    create_refresh_token,
    create_sso_token,
    decode_access_token,
    decode_sso_token,
    revoke_refresh_token,
    store_refresh_token,
    validate_refresh_token,
)
from src.app.services.user import (
    AccountExistsWithDifferentMethodError,
    EmailAlreadyRegisteredError,
    authenticate_user,
    create_email_user,
    find_or_create_oauth_user,
)
from src.app.utils.crypto import MAX_PASSWORD_BYTES, hash_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]
# Fail-open Redis handle for the rate limiter — yields None if Redis is down so
# a limiter-backend outage degrades to "no limiting" rather than a 500.
RateLimitRedisDep = Annotated[Redis | None, Depends(get_redis_optional)]

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
# The verified email is already registered under a *different* auth method
# (a password, or another OAuth provider). We refuse to silently link the new
# provider (#153 / #154); the frontend renders "{email} is already registered
# as {method}" using the accompanying `method` query param.
OAUTH_ERROR_ACCOUNT_EXISTS = "account_exists_different_method"
OAUTH_ERROR_PROVIDER_DENIED = "provider_denied"
OAUTH_ERROR_UNSUPPORTED_PROVIDER = "unsupported_provider"
OAUTH_ERROR_RATE_LIMITED = "rate_limited"
# DB-layer failure during find-or-create (connection drop, lock timeout,
# constraint violation, missing schema). Distinct from email_mismatch so the
# frontend can render "try again later" rather than a user-actionable message.
OAUTH_ERROR_UPSERT_FAILED = "oauth_upsert_failed"

VALID_PROVIDERS = {p.value for p in OAuthProvider}

# Identity headers emitted by GET /auth/forward-auth on success. Caddy's
# `forward_auth` copies these upstream to Grafana's auth-proxy (deploy#458), and
# strips any client-supplied X-Webauth-* before this hop so they cannot be forged.
WEBAUTH_USER_HEADER = "X-Webauth-User"
WEBAUTH_ROLE_HEADER = "X-Webauth-Role"


# --- Email / Password Endpoints ---


async def _load_user_roles(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    """Fetch the role names assigned to a user (for access-token claims)."""
    roles_result = await db.execute(
        text(
            "SELECT r.name FROM roles r "
            "JOIN user_roles ur ON ur.role_id = r.id "
            "WHERE ur.user_id = :uid"
        ),
        {"uid": user_id},
    )
    return [row[0] for row in roles_result.fetchall()]


async def _issue_token_pair(
    *,
    settings: Settings,
    db: AsyncSession,
    request: Request,
    user_id: uuid.UUID,
    email: str,
    roles: list[str],
    subscription_status: str,
) -> TokenResponse:
    """Mint an access + refresh token pair and persist the refresh token.

    Shared by the email login and register endpoints; produces the same
    `TokenResponse` shape as the OAuth `/auth/token` exchange so every login
    path hands the frontend an identical token contract.
    """
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


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    rl_redis: RateLimitRedisDep,
) -> TokenResponse:
    """Register a new email/password user and return a token pair (auto-login).

    The account is created with `email_verified=False` — the caller is logged in
    immediately for parity with the OAuth flow, and email verification is handled
    out-of-band by the verification subsystem.
    """
    await enforce_ip_rate_limit(request, rl_redis, settings, bucket="register")

    # Configurable policy minimum (settings) layered over the schema's coarse
    # bounds. Enforced here because the schema is static and cannot read settings.
    if len(body.password) < settings.AUTH_PASSWORD_MIN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must be at least {settings.AUTH_PASSWORD_MIN_LENGTH} characters",
        )
    # bcrypt silently truncates beyond 72 bytes — reject rather than hash a
    # value whose tail is ignored (two passwords sharing a 72-byte prefix would
    # otherwise authenticate interchangeably).
    if len(body.password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must not exceed {MAX_PASSWORD_BYTES} bytes",
        )

    password_hash = hash_password(body.password)
    try:
        user = await create_email_user(
            db,
            email=body.email,
            password_hash=password_hash,
            display_name=body.display_name,
        )
    except EmailAlreadyRegisteredError as exc:
        # Generic message — the status code already implies existence on this
        # surface, so we avoid echoing the address back.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc

    subscription_status = await get_subscription_status(db, user.id)
    return await _issue_token_pair(
        settings=settings,
        db=db,
        request=request,
        user_id=user.id,
        email=user.email,
        roles=[],  # fresh account has no roles yet
        subscription_status=subscription_status,
    )


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(
    body: LoginRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    rl_redis: RateLimitRedisDep,
) -> TokenResponse:
    """Authenticate an email/password user and return a token pair.

    On any failure (unknown email, wrong password, OAuth-only account, or a
    deactivated account) the response is a single generic 401 so the endpoint
    never reveals which emails are registered.
    """
    await enforce_ip_rate_limit(request, rl_redis, settings, bucket="login")

    user = await authenticate_user(db, email=body.email, password=body.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user.last_login_at = datetime.now(UTC)
    roles = await _load_user_roles(db, user.id)
    subscription_status = await get_subscription_status(db, user.id)
    # store_refresh_token commits the session, persisting the last_login_at touch.
    return await _issue_token_pair(
        settings=settings,
        db=db,
        request=request,
        user_id=user.id,
        email=user.email,
        roles=roles,
        subscription_status=subscription_status,
    )


@router.get("/providers", response_model=ProvidersResponse)
async def list_providers(settings: SettingsDep) -> ProvidersResponse:
    """List the auth methods this service supports and whether each is enabled.

    Email/password is always available; each OAuth provider is `enabled` only
    when its credentials are configured. The frontend uses this to render the
    correct set of login buttons.
    """
    providers = [AuthProviderInfo(id="email", type="password", enabled=True)]
    providers.extend(
        AuthProviderInfo(
            id=provider.value,
            type="oauth",
            enabled=is_oauth_provider_configured(provider, settings),
        )
        for provider in OAuthProvider
    )
    return ProvidersResponse(providers=providers)


# --- JWT Token Endpoints ---


@router.post("/token", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def issue_token(
    body: TokenRequest,
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    redis: RedisDep,
    rl_redis: RateLimitRedisDep,
) -> TokenResponse:
    """Issue an access + refresh token pair after OAuth success.

    Requires a one-time authorization code issued by the OAuth callback endpoint.
    The code is single-use and expires after 60 seconds.
    """
    await enforce_ip_rate_limit(request, rl_redis, settings, bucket="token")

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
    rl_redis: RateLimitRedisDep,
) -> TokenResponse:
    """Exchange a refresh token for a new access token (with rotation)."""
    # Rate-limit by IP before touching the token store — blocks a single host
    # from hammering refresh/rotation regardless of which token it presents.
    await enforce_ip_rate_limit(request, rl_redis, settings, bucket="refresh")

    session = await validate_refresh_token(db, body.refresh_token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Secondary per-user rate limit: caps refresh churn for one account even if
    # the attacker rotates source IPs. Keyed by user_id, separate bucket.
    await check_rate_limit(
        rl_redis,
        settings,
        bucket="refresh_user",
        identifier=str(session.user_id),
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
    request: Request,
    settings: SettingsDep,
    rl_redis: RateLimitRedisDep,
    authorization: Annotated[str, Header()],
) -> TokenValidationResponse:
    """Validate an access token (for cross-service calls)."""
    await enforce_ip_rate_limit(request, rl_redis, settings, bucket="validate")

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


# --- SSO Session Cookie + Forward-Auth (us#171 / deploy#458) ---


def _highest_role(roles: list[str]) -> str:
    """Return the highest-privilege role name from a claim (for X-Webauth-Role).

    Empty string when the user has no recognized role — never reached on the 200
    path of forward-auth (which requires admin), but keeps the header well-defined.
    """
    return max(roles, key=get_role_level, default="")


@router.post("/sso-cookie", response_model=SsoCookieResponse, status_code=status.HTTP_200_OK)
async def issue_sso_cookie(
    response: Response,
    settings: SettingsDep,
    db: DbDep,
    user: Annotated[User, Depends(get_current_user)],
) -> SsoCookieResponse:
    """Mint a short-lived parent-domain SSO cookie from a valid app bearer.

    The frontend calls this on a `/grafana` click (carrying its localStorage access
    token as a normal Bearer) so the *next* top-level browser navigation to a
    sibling subdomain (`isnad.{base}/grafana`) ships a credential Caddy's
    `forward_auth` can validate via `GET /auth/forward-auth`.

    Any authenticated user may mint — admin gating happens at forward-auth, not
    here, so a non-admin still receives a cookie and is cleanly rejected (403) at
    the Grafana edge rather than being unable to obtain a cookie at all. Roles are
    read authoritatively from the DB at mint time; the short TTL bounds staleness.
    """
    roles = await get_user_role_names(db, user.id)
    _token, _expires_at = create_sso_token(
        settings=settings,
        user_id=user.id,
        email=user.email,
        roles=roles,
        ttl_seconds=settings.AUTH_SSO_COOKIE_TTL_SECONDS,
    )
    # Parent-domain + path=/ so the cookie rides every top-level nav to any
    # *.{domain} subdomain. HttpOnly keeps it out of JS (the access token already
    # covers same-origin fetches); Secure + SameSite=Lax per the owner-approved
    # trade-off (us#171).
    response.set_cookie(
        key=settings.AUTH_SSO_COOKIE_NAME,
        value=_token,
        max_age=settings.AUTH_SSO_COOKIE_TTL_SECONDS,
        domain=settings.AUTH_SSO_COOKIE_DOMAIN,
        httponly=True,
        secure=settings.AUTH_SSO_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return SsoCookieResponse(
        cookie_name=settings.AUTH_SSO_COOKIE_NAME,
        expires_in=settings.AUTH_SSO_COOKIE_TTL_SECONDS,
    )


@router.get("/forward-auth", response_model=ForwardAuthResponse)
async def forward_auth(
    request: Request,
    response: Response,
    settings: SettingsDep,
) -> ForwardAuthResponse:
    """Cookie-based forward-auth gate for Caddy's `forward_auth` (deploy#458).

    Validates the parent-domain SSO cookie minted by `POST /auth/sso-cookie` and
    authorizes admin-only access to the observability surface (Grafana):

      - no / invalid / expired cookie  → 401
      - valid cookie, non-admin role   → 403
      - valid cookie, admin role       → 200 + X-Webauth-User / X-Webauth-Role

    Distinct from the Bearer-only `GET /auth/token/validate`: this reads a *cookie*,
    not an Authorization header, because the triggering request is a top-level
    browser navigation that carries no Bearer. The admin decision is made
    server-side from the RS256-signed cookie claims — the client cannot forge it,
    and Caddy strips any client-supplied `X-Webauth-*` before this hop.
    """
    cookie = request.cookies.get(settings.AUTH_SSO_COOKIE_NAME)
    if not cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing SSO session cookie",
        )

    try:
        payload = decode_sso_token(settings, cookie)
    except JWTError as err:
        # Bad signature, wrong token type, or expiry — all collapse to 401 so the
        # endpoint never distinguishes "no cookie" from "forged/stale cookie".
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SSO session cookie",
        ) from err

    roles: list[str] = payload.get("roles", [])
    if not user_has_minimum_role(roles, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    # Identity for Grafana's auth-proxy. Prefer email (a human-friendly login);
    # fall back to the user id (`sub`) if the cookie carried no email.
    response.headers[WEBAUTH_USER_HEADER] = str(payload.get("email") or payload.get("sub", ""))
    response.headers[WEBAUTH_ROLE_HEADER] = _highest_role(roles)
    return ForwardAuthResponse()


# --- OAuth Endpoints ---


def _build_post_login_url(
    settings: Settings,
    provider: str,
    params: dict[str, str],
    fragment_params: dict[str, str] | None = None,
) -> str:
    """Build the post-login redirect URL.

    `AUTH_OAUTH_POST_LOGIN_URL` is the BASE path (e.g. `/auth/callback`); the
    `/{provider}` segment is always appended here so the URL matches the
    frontend's React Router route `auth/callback/:provider` (required param).
    Per review on #66 / fix for isnad-graph#824 — picked option (a) from Anya's
    review: setting is base, provider is always appended by the handler. This
    avoids template-substitution footguns ({provider} stray braces, missing
    placeholders, etc.) and keeps the setting a plain path string.

    `provider` comes from the FastAPI path parameter, which is validated
    against `VALID_PROVIDERS` in every caller — never user-supplied arbitrary
    text at this point.

    `params` are emitted as the query string; `fragment_params` (if any) are
    emitted as the URL fragment. Per #68, the access token is delivered in the
    fragment so it never leaks via the `Referer` header — fragments are not
    sent in `Referer` by any browser. Non-secret flags (`is_new_user`,
    `needs_verification`, `error`) stay as query params so SSR / server logs
    can still observe them.
    """
    base = (settings.AUTH_OAUTH_POST_LOGIN_URL or "/").rstrip("/")
    # URL-encode the provider even though we only ever pass validated values —
    # belt-and-braces in case VALID_PROVIDERS ever includes a special character.
    path = f"{base}/{urllib.parse.quote(provider, safe='')}"
    if params:
        path = f"{path}?{urllib.parse.urlencode(params)}"
    if fragment_params:
        path = f"{path}#{urllib.parse.urlencode(fragment_params)}"
    return path


def _build_error_redirect(
    settings: Settings,
    provider: str,
    error_code: str,
    extra_params: dict[str, str] | None = None,
) -> RedirectResponse:
    """Build a RedirectResponse to the frontend post-login URL with an error param.

    `extra_params` adds non-secret query params alongside `error` (e.g. the
    `method` the email is already registered as, for the account_exists case).
    """
    params = {"error": error_code}
    if extra_params:
        params.update(extra_params)
    url = _build_post_login_url(settings, provider, params)
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
    rl_redis: RateLimitRedisDep,
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
    # Per-IP rate limit. This endpoint is browser-facing, so a raised 429 would
    # be a dead end — instead bounce to the frontend with a rate_limited error
    # code (consistent with every other exit path here).
    try:
        await enforce_ip_rate_limit(request, rl_redis, settings, bucket="oauth_callback")
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            return _build_error_redirect(settings, provider, OAUTH_ERROR_RATE_LIMITED)
        raise

    # Provider-denied consent (e.g. "access_denied") → bounce to frontend with error
    if error:
        return _build_error_redirect(settings, provider, OAUTH_ERROR_PROVIDER_DENIED)

    if provider not in VALID_PROVIDERS:
        return _build_error_redirect(settings, provider, OAUTH_ERROR_UNSUPPORTED_PROVIDER)

    if not code or not state:
        return _build_error_redirect(settings, provider, OAUTH_ERROR_INVALID_STATE)

    # Validate state (CSRF) and fetch the PKCE code_verifier. getdel() ensures the
    # state is consumed exactly once — replay of the same callback URL is blocked.
    state_key = f"{OAUTH_STATE_PREFIX}{state}"
    raw_state = await redis.getdel(state_key)
    if raw_state is None:
        return _build_error_redirect(settings, provider, OAUTH_ERROR_INVALID_STATE)

    state_data: dict[str, str] = json.loads(raw_state)
    # Defense in depth: the state entry is keyed by provider at create time; if the
    # user tampered with the `{provider}` path segment, refuse.
    if state_data.get("provider") != provider:
        return _build_error_redirect(settings, provider, OAUTH_ERROR_INVALID_STATE)
    code_verifier = state_data["code_verifier"]

    redirect_uri = f"{settings.AUTH_OAUTH_REDIRECT_BASE_URL}/auth/oauth/{provider}/callback"
    oauth = get_oauth_provider(provider, settings)

    # Exchange code → provider tokens. Provider failures (network, 4xx, malformed
    # response) must bounce the user back with a readable error, not leak as 500.
    try:
        tokens = await oauth.exchange_code(code, code_verifier, redirect_uri)
    except httpx.HTTPStatusError as exc:
        # Provider returned a 4xx/5xx — body usually contains the error code
        # (e.g. invalid_grant, redirect_uri_mismatch). Excerpt is safe to log:
        # OAuth error responses are diagnostic codes, not user data.
        body_excerpt = exc.response.text[:500]
        logger.exception(
            "OAuth exchange HTTP error: provider=%s redirect_uri=%s status=%s body=%s",
            provider,
            redirect_uri,
            exc.response.status_code,
            body_excerpt,
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_EXCHANGE_FAILED)
    except Exception as exc:
        logger.exception(
            "OAuth exchange unexpected error: provider=%s redirect_uri=%s exc_type=%s",
            provider,
            redirect_uri,
            type(exc).__name__,
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_EXCHANGE_FAILED)

    # Fetch user info. Apple returns identity in the id_token; others use access_token.
    if provider == "apple":
        token_for_user_info: str = tokens.get("id_token", "")
    else:
        token_for_user_info = tokens.get("access_token", "")

    try:
        user_info = await oauth.get_user_info(token_for_user_info)
    except httpx.HTTPStatusError as exc:
        body_excerpt = exc.response.text[:500]
        logger.exception(
            "OAuth user_info HTTP error: provider=%s status=%s body=%s",
            provider,
            exc.response.status_code,
            body_excerpt,
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_USER_INFO_FAILED)
    except Exception as exc:
        logger.exception(
            "OAuth user_info unexpected error: provider=%s exc_type=%s",
            provider,
            type(exc).__name__,
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_USER_INFO_FAILED)

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
    except SQLAlchemyError as exc:
        # Any DB-layer failure (connection drop, lock timeout, constraint
        # violation, missing schema — e.g. ProgrammingError "relation does not
        # exist"). Without this catch these bubble up as a raw 500 instead of a
        # friendly redirect (#73). Caught BEFORE ValueError: the two are disjoint
        # exception trees, but SQLAlchemyError is the broad base class so every
        # DBAPIError/IntegrityError/OperationalError/ProgrammingError subclass is
        # covered. Log full detail server-side via logger.exception; the redirect
        # carries only a generic code — DB exception strings can contain table
        # names, SQL, and connection params and must never reach the browser.
        logger.exception(
            "OAuth upsert DB error: provider=%s exc_type=%s",
            provider,
            type(exc).__name__,
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_UPSERT_FAILED)
    except AccountExistsWithDifferentMethodError as exc:
        # The verified email already belongs to an account using a *different*
        # auth method (password, or another OAuth provider). We refuse to
        # silently link the new provider (#153 / #154) — surface a clear,
        # user-facing error carrying the existing primary method so the
        # frontend can render "{email} is already registered as {method}".
        logger.warning(
            "OAuth cross-method link blocked: provider=%s existing_methods=%s",
            provider,
            ",".join(exc.existing_methods),
        )
        return _build_error_redirect(
            settings,
            provider,
            OAUTH_ERROR_ACCOUNT_EXISTS,
            {"method": exc.primary_method},
        )
    except ValueError as exc:
        # Missing email / email-mismatch-style errors bounce the user back with a
        # readable error code the frontend can render.
        logger.warning(
            "OAuth user upsert rejected: provider=%s exc=%s",
            provider,
            str(exc)[:200],
        )
        return _build_error_redirect(settings, provider, OAUTH_ERROR_EMAIL_MISMATCH)

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
    # via redirect is already the single-use handoff). The access token goes in the
    # redirect URL *fragment* (the frontend AuthCallbackPage reads it from
    # window.location.hash and stores it in localStorage) so it never leaks via the
    # Referer header — see #68. The refresh token goes in an httpOnly cookie so JS
    # cannot read it.
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

    # Build the success redirect: the access token goes in the URL fragment (#68
    # — keeps it out of the Referer header), the non-secret flags stay as query
    # params. The `/{provider}` segment is appended by _build_post_login_url to
    # match the frontend route `auth/callback/:provider` (required param — see
    # isnad-graph/frontend/src/App.tsx:57 and isnad-graph#824).
    redirect_url = _build_post_login_url(
        settings,
        provider,
        {
            "is_new_user": "1" if result.is_new_user else "0",
            # OAuth users are created with email_verified=True, so verification is
            # never needed via this flow — but we emit the flag for frontend parity.
            "needs_verification": "0",
        },
        fragment_params={"token": access_token},
    )
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
