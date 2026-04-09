"""RSA key management for JWT signing.

Loads keys from settings (JWT_PRIVATE_KEY / JWT_PUBLIC_KEY env vars).
If no keys are configured, generates a dev key pair on first access.
"""

import base64
import hashlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.app.config import Settings

_dev_private_key: rsa.RSAPrivateKey | None = None
_dev_public_key: rsa.RSAPublicKey | None = None


def _ensure_dev_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a dev RSA key pair (only used when env vars are empty)."""
    global _dev_private_key, _dev_public_key
    if _dev_private_key is None:
        _dev_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        _dev_public_key = _dev_private_key.public_key()
    assert _dev_public_key is not None
    return _dev_private_key, _dev_public_key


def _maybe_b64_decode(value: str) -> str:
    """Decode base64-encoded PEM if needed. Pass through raw PEM unchanged."""
    if value.startswith("-----BEGIN"):
        return value
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception:
        return value


def get_private_key(settings: Settings) -> str:
    """Return the PEM-encoded private key string for JWT signing."""
    if settings.JWT_PRIVATE_KEY:
        return _maybe_b64_decode(settings.JWT_PRIVATE_KEY)
    priv, _ = _ensure_dev_keys()
    pem: bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode()


def get_public_key(settings: Settings) -> str:
    """Return the PEM-encoded public key string for JWT verification."""
    if settings.JWT_PUBLIC_KEY:
        return _maybe_b64_decode(settings.JWT_PUBLIC_KEY)
    _, pub = _ensure_dev_keys()
    pem: bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode()


def _int_to_base64url(n: int) -> str:
    """Convert an integer to a base64url-encoded string (no padding)."""
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")


def get_public_key_jwk(settings: Settings) -> dict[str, Any]:
    """Return the public key as a JWK dict for the JWKS endpoint."""
    pem = get_public_key(settings)
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    pub_key = load_pem_public_key(pem.encode())
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise TypeError("Only RSA public keys are supported")

    pub_numbers = pub_key.public_numbers()
    kid = hashlib.sha256(pem.encode()).hexdigest()[:16]

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }
