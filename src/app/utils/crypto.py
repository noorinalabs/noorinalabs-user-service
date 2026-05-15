"""Cryptographic helpers shared across services and routers."""

import hashlib


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of an opaque token.

    Used to store refresh tokens and verification tokens at rest as a hash
    rather than the raw value. Callers compare hashes, never raw tokens.
    """
    return hashlib.sha256(token.encode()).hexdigest()
