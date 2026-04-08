"""Verification service — US #8.

Handles email verification token generation, validation, rate limiting,
and email dispatch.
"""

from __future__ import annotations

import hashlib
import html
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings
from src.app.models.user import User
from src.app.models.verification_token import TokenType, VerificationToken


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def check_rate_limit(
    db: AsyncSession,
    user_id: uuid.UUID,
    settings: Settings,
) -> bool:
    """Return True if the user has NOT exceeded the rate limit."""
    window_start = datetime.now(UTC) - timedelta(
        minutes=settings.VERIFICATION_RATE_LIMIT_WINDOW_MINUTES
    )
    result = await db.execute(
        select(func.count())
        .select_from(VerificationToken)
        .where(
            VerificationToken.user_id == user_id,
            VerificationToken.token_type == TokenType.email_verification,
            VerificationToken.created_at >= window_start,
        )
    )
    count = result.scalar_one()
    return count < settings.VERIFICATION_RATE_LIMIT_MAX


async def invalidate_existing_tokens(
    db: AsyncSession,
    user_id: uuid.UUID,
) -> None:
    """Mark all unused verification tokens for a user as used (invalidated)."""
    await db.execute(
        update(VerificationToken)
        .where(
            VerificationToken.user_id == user_id,
            VerificationToken.token_type == TokenType.email_verification,
            VerificationToken.used_at.is_(None),
        )
        .values(used_at=datetime.now(UTC))
    )


async def create_verification_token(
    db: AsyncSession,
    user_id: uuid.UUID,
    settings: Settings,
) -> str:
    """Create a new verification token. Invalidates any existing tokens first.

    Returns the raw (unhashed) token for inclusion in the email.
    """
    await invalidate_existing_tokens(db, user_id)

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_TOKEN_EXPIRE_HOURS)

    verification_token = VerificationToken(
        user_id=user_id,
        token_hash=token_hash,
        token_type=TokenType.email_verification,
        expires_at=expires_at,
    )
    db.add(verification_token)
    await db.flush()
    return raw_token


async def confirm_verification_token(
    db: AsyncSession,
    raw_token: str,
) -> User | None:
    """Validate a verification token and mark the user's email as verified.

    Returns the User if successful, None if the token is invalid/expired/used.
    """
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    result = await db.execute(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.token_type == TokenType.email_verification,
            VerificationToken.used_at.is_(None),
            VerificationToken.expires_at > now,
        )
    )
    verification = result.scalar_one_or_none()
    if verification is None:
        return None

    # Mark token as used
    verification.used_at = now

    # Mark user email as verified
    user_result = await db.execute(
        select(User).where(User.id == verification.user_id)
    )
    user = user_result.scalar_one_or_none()
    if user is None:
        return None

    user.email_verified = True
    await db.flush()
    return user


async def get_latest_verification_token(
    db: AsyncSession,
    user_id: uuid.UUID,
) -> VerificationToken | None:
    """Get the most recent verification token for a user."""
    result = await db.execute(
        select(VerificationToken)
        .where(
            VerificationToken.user_id == user_id,
            VerificationToken.token_type == TokenType.email_verification,
        )
        .order_by(VerificationToken.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _build_verification_email(
    to_email: str,
    verification_url: str,
    settings: Settings,
) -> MIMEMultipart:
    """Build the HTML verification email."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Verify your email — NoorinALabs"
    msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
    msg["To"] = to_email

    text_body = (
        f"Welcome to NoorinALabs!\n\n"
        f"Please verify your email by visiting:\n{verification_url}\n\n"
        f"This link expires in {settings.VERIFICATION_TOKEN_EXPIRE_HOURS} hours.\n\n"
        f"If you did not create an account, you can ignore this email."
    )

    safe_url = html.escape(verification_url)
    expire_hours = settings.VERIFICATION_TOKEN_EXPIRE_HOURS

    html_body = f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a2e;">Welcome to NoorinALabs</h2>
  <p>Please verify your email address by clicking the button below:</p>
  <p style="text-align: center; margin: 30px 0;">
    <a href="{safe_url}"
       style="background-color: #16213e; color: #ffffff; padding: 12px 32px;
              text-decoration: none; border-radius: 6px; display: inline-block;
              font-weight: 600;">
      Verify Email
    </a>
  </p>
  <p style="color: #666; font-size: 14px;">
    Or copy this link into your browser:<br>
    <a href="{safe_url}">{safe_url}</a>
  </p>
  <p style="color: #999; font-size: 12px;">
    This link expires in {expire_hours} hours.
    If you did not create an account, you can safely ignore this email.
  </p>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    return msg


async def send_verification_email(
    to_email: str,
    raw_token: str,
    settings: Settings,
) -> None:
    """Send the verification email via SMTP."""
    verification_url = f"{settings.VERIFICATION_BASE_URL}/verify-email?token={raw_token}"
    msg = _build_verification_email(to_email, verification_url, settings)

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USERNAME or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_START_TLS,
    )
