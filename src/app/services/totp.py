"""TOTP service — US #10.

Handles TOTP secret generation, encryption at rest, verification,
recovery codes, and 2FA lifecycle management.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings
from src.app.models.totp_secret import TOTPSecret


def _get_fernet(settings: Settings) -> Fernet:
    """Get a Fernet instance for encrypting/decrypting TOTP secrets."""
    if not settings.TOTP_ENCRYPTION_KEY:
        msg = (
            "TOTP_ENCRYPTION_KEY must be set. "
            "Generate one with: python -c "
            '"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
        raise ValueError(msg)
    return Fernet(settings.TOTP_ENCRYPTION_KEY.encode())


def encrypt_secret(plaintext: str, settings: Settings) -> str:
    """Encrypt a TOTP secret for storage."""
    f = _get_fernet(settings)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str, settings: Settings) -> str:
    """Decrypt a stored TOTP secret."""
    f = _get_fernet(settings)
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken as err:
        msg = "Failed to decrypt TOTP secret — encryption key may have changed"
        raise ValueError(msg) from err


def generate_recovery_codes(count: int) -> list[str]:
    """Generate a list of single-use recovery codes."""
    return [secrets.token_hex(4) + "-" + secrets.token_hex(4) for _ in range(count)]


def _hash_recovery_codes(codes: list[str]) -> str:
    """Hash recovery codes for storage. Returns JSON array of hashes."""
    hashed = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
    return json.dumps(hashed)


def _verify_recovery_code(code: str, stored_hashes_json: str) -> tuple[bool, str]:
    """Check a recovery code against stored hashes.

    Returns (matched, updated_hashes_json) — the matched hash is removed.
    """
    hashes: list[str] = json.loads(stored_hashes_json)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if code_hash in hashes:
        hashes.remove(code_hash)
        return True, json.dumps(hashes)
    return False, stored_hashes_json


async def get_totp_secret(
    db: AsyncSession,
    user_id: Any,
) -> TOTPSecret | None:
    """Get the active TOTP secret for a user."""
    result = await db.execute(
        select(TOTPSecret).where(
            TOTPSecret.user_id == user_id,
            TOTPSecret.disabled_at.is_(None),
        )
    )
    return result.scalar_one_or_none()


async def setup_totp(
    db: AsyncSession,
    user_id: Any,
    email: str,
    settings: Settings,
) -> tuple[str, str, list[str]]:
    """Generate a new TOTP secret for a user.

    Returns (raw_secret, provisioning_uri, recovery_codes).
    Replaces any existing unverified secret.
    """
    # Remove any existing unverified secret
    existing = await get_totp_secret(db, user_id)
    if existing is not None:
        if existing.is_verified:
            msg = "2FA is already enabled — disable it first to re-setup"
            raise ValueError(msg)
        await db.delete(existing)
        await db.flush()

    raw_secret = pyotp.random_base32()
    encrypted = encrypt_secret(raw_secret, settings)

    recovery_codes = generate_recovery_codes(settings.TOTP_RECOVERY_CODE_COUNT)
    hashed_codes = _hash_recovery_codes(recovery_codes)

    totp_obj = pyotp.TOTP(raw_secret)
    provisioning_uri = totp_obj.provisioning_uri(
        name=email,
        issuer_name=settings.TOTP_ISSUER_NAME,
    )

    totp_secret = TOTPSecret(
        user_id=user_id,
        encrypted_secret=encrypted,
        recovery_codes=hashed_codes,
    )
    db.add(totp_secret)
    await db.flush()

    return raw_secret, provisioning_uri, recovery_codes


async def verify_totp_setup(
    db: AsyncSession,
    user_id: Any,
    code: str,
    settings: Settings,
) -> bool:
    """Verify a TOTP code to confirm 2FA setup. Returns True on success."""
    secret = await get_totp_secret(db, user_id)
    if secret is None or secret.is_verified:
        return False

    raw_secret = decrypt_secret(secret.encrypted_secret, settings)
    totp = pyotp.TOTP(raw_secret)

    if not totp.verify(code, valid_window=1):
        return False

    secret.is_verified = True
    secret.verified_at = datetime.now(UTC)
    await db.flush()
    return True


async def verify_totp_code(
    db: AsyncSession,
    user_id: Any,
    code: str,
    settings: Settings,
) -> bool:
    """Verify a TOTP code for an already-enabled 2FA user.

    Also accepts recovery codes.
    """
    secret = await get_totp_secret(db, user_id)
    if secret is None or not secret.is_verified:
        return False

    # Try TOTP code first
    raw_secret = decrypt_secret(secret.encrypted_secret, settings)
    totp = pyotp.TOTP(raw_secret)
    if totp.verify(code, valid_window=1):
        return True

    # Try recovery code
    if secret.recovery_codes:
        matched, updated = _verify_recovery_code(code, secret.recovery_codes)
        if matched:
            secret.recovery_codes = updated
            await db.flush()
            return True

    return False


async def disable_totp(
    db: AsyncSession,
    user_id: Any,
    code: str,
    settings: Settings,
) -> bool:
    """Disable 2FA after verifying a current TOTP code. Returns True on success."""
    secret = await get_totp_secret(db, user_id)
    if secret is None or not secret.is_verified:
        return False

    # Verify the code before allowing disable
    raw_secret = decrypt_secret(secret.encrypted_secret, settings)
    totp = pyotp.TOTP(raw_secret)

    code_valid = totp.verify(code, valid_window=1)
    # Also allow recovery codes for disable — consume on use
    recovery_valid = False
    if not code_valid and secret.recovery_codes:
        recovery_valid, updated_codes = _verify_recovery_code(code, secret.recovery_codes)
        if recovery_valid:
            secret.recovery_codes = updated_codes

    if not code_valid and not recovery_valid:
        return False

    secret.disabled_at = datetime.now(UTC)
    await db.flush()
    return True


def is_2fa_enabled(totp_secret: TOTPSecret | None) -> bool:
    """Check if 2FA is enabled and verified for a user."""
    return totp_secret is not None and totp_secret.is_verified
