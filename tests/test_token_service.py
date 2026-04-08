"""Unit tests for JWT token lifecycle — keys, signing, validation, JWKS."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from jose import JWTError, jwt

from src.app.config import Settings
from src.app.services.keys import (
    get_private_key,
    get_public_key,
    get_public_key_jwk,
)
from src.app.services.token import (
    _hash_token,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    get_jwks,
)


def _test_settings() -> Settings:
    """Return a Settings instance with empty keys (triggers dev key generation)."""
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_PRIVATE_KEY="",
        JWT_PUBLIC_KEY="",
    )


class TestKeyManagement:
    def test_dev_keys_generated_when_empty(self) -> None:
        settings = _test_settings()
        priv = get_private_key(settings)
        pub = get_public_key(settings)
        assert "BEGIN PRIVATE KEY" in priv
        assert "BEGIN PUBLIC KEY" in pub

    def test_dev_keys_are_stable(self) -> None:
        settings = _test_settings()
        assert get_private_key(settings) == get_private_key(settings)
        assert get_public_key(settings) == get_public_key(settings)

    def test_explicit_keys_used_when_provided(self) -> None:
        settings = _test_settings()
        # Generate a key pair via dev keys, then pass them explicitly
        priv = get_private_key(settings)
        pub = get_public_key(settings)

        explicit_settings = Settings(
            DATABASE_URL="sqlite+aiosqlite:///:memory:",
            JWT_PRIVATE_KEY=priv,
            JWT_PUBLIC_KEY=pub,
        )
        assert get_private_key(explicit_settings) == priv
        assert get_public_key(explicit_settings) == pub


class TestJWKS:
    def test_jwk_structure(self) -> None:
        settings = _test_settings()
        jwk = get_public_key_jwk(settings)
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "kid" in jwk
        assert "n" in jwk
        assert "e" in jwk

    def test_jwks_response(self) -> None:
        settings = _test_settings()
        jwks = get_jwks(settings)
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kty"] == "RSA"


class TestAccessToken:
    def test_create_and_decode(self) -> None:
        settings = _test_settings()
        user_id = uuid.uuid4()
        email = "test@example.com"
        roles = ["researcher"]

        token, expires_at = create_access_token(settings, user_id, email, roles, "active")
        assert isinstance(token, str)
        assert expires_at > datetime.now(UTC)

        payload = decode_access_token(settings, token)
        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["roles"] == roles
        assert payload["subscription_status"] == "active"
        assert payload["type"] == "access"

    def test_expired_token_rejected(self) -> None:
        settings = _test_settings()
        priv = get_private_key(settings)
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "test@example.com",
            "roles": [],
            "subscription_status": "free",
            "iat": datetime.now(UTC) - timedelta(hours=1),
            "exp": datetime.now(UTC) - timedelta(minutes=1),
            "type": "access",
        }
        token: str = jwt.encode(payload, priv, algorithm="RS256")
        with pytest.raises(JWTError):
            decode_access_token(settings, token)

    def test_wrong_type_rejected(self) -> None:
        settings = _test_settings()
        priv = get_private_key(settings)
        payload = {
            "sub": str(uuid.uuid4()),
            "email": "test@example.com",
            "roles": [],
            "subscription_status": "free",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=15),
            "type": "refresh",
        }
        token: str = jwt.encode(payload, priv, algorithm="RS256")
        with pytest.raises(JWTError, match="Not an access token"):
            decode_access_token(settings, token)

    def test_tampered_token_rejected(self) -> None:
        settings = _test_settings()
        user_id = uuid.uuid4()
        token, _ = create_access_token(settings, user_id, "test@example.com", [], "free")
        # Tamper with the token
        tampered = token[:-4] + "XXXX"
        with pytest.raises(JWTError):
            decode_access_token(settings, tampered)

    def test_access_token_expiry_is_15_min(self) -> None:
        settings = _test_settings()
        _, expires_at = create_access_token(settings, uuid.uuid4(), "t@t.com", [], "free")
        expected = datetime.now(UTC) + timedelta(minutes=15)
        # Allow 5 seconds tolerance
        assert abs((expires_at - expected).total_seconds()) < 5


class TestRefreshToken:
    def test_refresh_token_is_random(self) -> None:
        t1 = create_refresh_token()
        t2 = create_refresh_token()
        assert t1 != t2
        assert len(t1) > 32  # 48 bytes base64url ≈ 64 chars

    def test_hash_is_deterministic(self) -> None:
        token = create_refresh_token()
        assert _hash_token(token) == _hash_token(token)

    def test_different_tokens_different_hashes(self) -> None:
        t1 = create_refresh_token()
        t2 = create_refresh_token()
        assert _hash_token(t1) != _hash_token(t2)
