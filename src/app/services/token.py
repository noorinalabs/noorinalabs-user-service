"""Token service — JWT issuance, validation, refresh, and revocation."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import jwt
from jose.exceptions import JWTError
from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings
from src.app.models.session import Session
from src.app.services.keys import get_private_key, get_public_key, get_public_key_jwk


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(
    settings: Settings,
    user_id: uuid.UUID,
    email: str,
    roles: list[str],
    subscription_status: str,
) -> tuple[str, datetime]:
    """Create a signed RS256 access token. Returns (token, expires_at)."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "roles": roles,
        "subscription_status": subscription_status,
        "iat": now,
        "exp": expires_at,
        "type": "access",
    }
    private_key = get_private_key(settings)
    token: str = jwt.encode(  # type: ignore[no-untyped-call]
        payload, private_key, algorithm=settings.JWT_ALGORITHM
    )
    return token, expires_at


def create_refresh_token() -> str:
    """Create a cryptographically random refresh token."""
    return secrets.token_urlsafe(48)


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Decode and validate an access token. Raises JWTError on failure."""
    public_key = get_public_key(settings)
    payload: dict[str, Any] = jwt.decode(  # type: ignore[no-untyped-call]
        token,
        public_key,
        algorithms=[settings.JWT_ALGORITHM],
    )
    if payload.get("type") != "access":
        raise JWTError("Not an access token")
    return payload


async def store_refresh_token(
    db: AsyncSession,
    user_id: uuid.UUID,
    refresh_token: str,
    expires_days: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Session:
    """Store a hashed refresh token in the sessions table."""
    token_hash = _hash_token(refresh_token)
    expires_at = datetime.now(UTC) + timedelta(days=expires_days)
    session = Session(
        user_id=user_id,
        token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )
    db.add(session)
    await db.commit()
    return session


async def validate_refresh_token(db: AsyncSession, refresh_token: str) -> Session | None:
    """Look up a refresh token and return the session if valid."""
    token_hash = _hash_token(refresh_token)
    now = datetime.now(UTC)
    result = await db.execute(
        select(Session).where(
            Session.token_hash == token_hash,
            Session.revoked_at.is_(None),
            Session.expires_at > now,
        )
    )
    return result.scalar_one_or_none()


async def revoke_refresh_token(db: AsyncSession, refresh_token: str) -> bool:
    """Revoke a refresh token. Returns True if a token was revoked."""
    token_hash = _hash_token(refresh_token)
    cursor_result: CursorResult[Any] = await db.execute(  # type: ignore[assignment]
        update(Session)
        .where(Session.token_hash == token_hash, Session.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    await db.commit()
    return cursor_result.rowcount > 0


def get_jwks(settings: Settings) -> dict[str, Any]:
    """Return the JWKS containing the public key."""
    jwk = get_public_key_jwk(settings)
    return {"keys": [jwk]}
