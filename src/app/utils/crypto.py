"""Cryptographic helpers shared across services and routers."""

import hashlib

import bcrypt

# bcrypt only hashes the first 72 bytes of the input and (as of bcrypt 4.1+)
# *raises* on anything longer. Callers MUST reject over-length passwords before
# hashing (see ``MAX_PASSWORD_BYTES``) so two distinct passwords sharing a
# 72-byte prefix can never collide into the same hash. We use the maintained
# ``bcrypt`` library directly rather than passlib, whose 1.7.4 backend probe is
# broken against bcrypt 5.x.
MAX_PASSWORD_BYTES = 72


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of an opaque token.

    Used to store refresh tokens and verification tokens at rest as a hash
    rather than the raw value. Callers compare hashes, never raw tokens.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    """Hash a user password with bcrypt for storage in ``users.password_hash``.

    The caller is responsible for enforcing the password policy (min length and
    the bcrypt 72-byte ceiling, ``MAX_PASSWORD_BYTES``) before calling this.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Check a plaintext password against a stored bcrypt hash.

    Returns ``False`` (never raises) on a malformed stored hash or an
    over-length / non-encodable input so a corrupt row or an oversized login
    attempt degrades to "auth fails" rather than a 500.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
