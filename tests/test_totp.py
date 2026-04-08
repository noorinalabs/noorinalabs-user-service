"""Tests for 2FA/TOTP flow — US #10."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.dependencies import get_current_user
from src.app.main import create_app
from src.app.models.totp_secret import TOTPSecret
from src.app.models.user import User
from src.app.services.totp import (
    _hash_recovery_codes,
    _verify_recovery_code,
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    is_2fa_enabled,
    verify_totp_code,
)


def _test_settings() -> Settings:
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_PRIVATE_KEY="",
        JWT_PUBLIC_KEY="",
        TOTP_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        TOTP_ISSUER_NAME="TestApp",
        TOTP_RECOVERY_CODE_COUNT=8,
    )


def _mock_user(
    email: str = "test@example.com",
) -> User:
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = email
    user.email_verified = True
    user.is_active = True
    return user


@pytest.fixture
def settings() -> Settings:
    return _test_settings()


@pytest.fixture
def mock_user() -> User:
    return _mock_user()


@pytest.fixture
async def client(
    settings: Settings,
    mock_user: User,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    mock_session = AsyncMock()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db_session] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self, settings: Settings) -> None:
        plaintext = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_secret(plaintext, settings)
        assert encrypted != plaintext
        decrypted = decrypt_secret(encrypted, settings)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_fails(self, settings: Settings) -> None:
        plaintext = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_secret(plaintext, settings)
        other_settings = Settings(
            DATABASE_URL="sqlite+aiosqlite:///:memory:",
            TOTP_ENCRYPTION_KEY=Fernet.generate_key().decode(),
        )
        with pytest.raises(ValueError, match="Failed to decrypt"):
            decrypt_secret(encrypted, other_settings)


class TestRecoveryCodes:
    def test_generate_count(self) -> None:
        codes = generate_recovery_codes(8)
        assert len(codes) == 8
        assert all("-" in code for code in codes)

    def test_codes_are_unique(self) -> None:
        codes = generate_recovery_codes(100)
        assert len(set(codes)) == 100

    def test_hash_and_verify(self) -> None:
        codes = generate_recovery_codes(4)
        hashed = _hash_recovery_codes(codes)
        hashes = json.loads(hashed)
        assert len(hashes) == 4

        matched, updated = _verify_recovery_code(codes[0], hashed)
        assert matched is True
        remaining = json.loads(updated)
        assert len(remaining) == 3

    def test_verify_invalid_code(self) -> None:
        codes = generate_recovery_codes(4)
        hashed = _hash_recovery_codes(codes)
        matched, updated = _verify_recovery_code("invalid-code", hashed)
        assert matched is False
        assert updated == hashed

    def test_code_consumed_once(self) -> None:
        codes = generate_recovery_codes(2)
        hashed = _hash_recovery_codes(codes)

        matched1, updated1 = _verify_recovery_code(codes[0], hashed)
        assert matched1 is True
        matched2, _updated2 = _verify_recovery_code(codes[0], updated1)
        assert matched2 is False


class TestIs2FAEnabled:
    def test_none_secret(self) -> None:
        assert is_2fa_enabled(None) is False

    def test_unverified_secret(self) -> None:
        secret = MagicMock(spec=TOTPSecret)
        secret.is_verified = False
        assert is_2fa_enabled(secret) is False

    def test_verified_secret(self) -> None:
        secret = MagicMock(spec=TOTPSecret)
        secret.is_verified = True
        assert is_2fa_enabled(secret) is True


class TestSetupEndpoint:
    async def test_setup_success(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.setup_totp",
            new_callable=AsyncMock,
            return_value=("SECRET", "otpauth://totp/test", ["code1", "code2"]),
        ):
            resp = await client.post("/2fa/setup")
            assert resp.status_code == 200
            data = resp.json()
            assert data["secret"] == "SECRET"
            assert "otpauth://" in data["provisioning_uri"]
            assert len(data["recovery_codes"]) == 2

    async def test_setup_already_enabled(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.setup_totp",
            new_callable=AsyncMock,
            side_effect=ValueError("2FA is already enabled"),
        ):
            resp = await client.post("/2fa/setup")
            assert resp.status_code == 400
            assert "already enabled" in resp.json()["detail"]


class TestVerifyEndpoint:
    async def test_verify_success(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.verify_totp_setup",
            new_callable=AsyncMock,
            return_value=True,
        ):
            resp = await client.post("/2fa/verify", json={"code": "123456"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["two_factor_enabled"] is True

    async def test_verify_invalid_code(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.verify_totp_setup",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = await client.post("/2fa/verify", json={"code": "000000"})
            assert resp.status_code == 400

    async def test_verify_code_too_short(self, client: AsyncClient) -> None:
        resp = await client.post("/2fa/verify", json={"code": "123"})
        assert resp.status_code == 422


class TestDisableEndpoint:
    async def test_disable_success(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.disable_totp",
            new_callable=AsyncMock,
            return_value=True,
        ):
            resp = await client.post("/2fa/disable", json={"code": "123456"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["two_factor_enabled"] is False

    async def test_disable_invalid_code(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.disable_totp",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = await client.post("/2fa/disable", json={"code": "000000"})
            assert resp.status_code == 400


class TestStatusEndpoint:
    async def test_status_enabled(self, client: AsyncClient) -> None:
        mock_secret = MagicMock(spec=TOTPSecret)
        mock_secret.is_verified = True
        with patch(
            "src.app.routers.totp.get_totp_secret",
            new_callable=AsyncMock,
            return_value=mock_secret,
        ):
            resp = await client.get("/2fa/status")
            assert resp.status_code == 200
            assert resp.json()["two_factor_enabled"] is True

    async def test_status_disabled(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.totp.get_totp_secret",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await client.get("/2fa/status")
            assert resp.status_code == 200
            assert resp.json()["two_factor_enabled"] is False


class TestVerifyTOTPCodeService:
    async def test_verify_valid_totp(self, settings: Settings) -> None:
        import pyotp

        raw_secret = pyotp.random_base32()
        encrypted = encrypt_secret(raw_secret, settings)
        totp = pyotp.TOTP(raw_secret)
        valid_code = totp.now()

        mock_secret = MagicMock(spec=TOTPSecret)
        mock_secret.is_verified = True
        mock_secret.encrypted_secret = encrypted
        mock_secret.recovery_codes = "[]"

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = mock_secret
        db.execute.return_value = result_mock

        result = await verify_totp_code(db, uuid.uuid4(), valid_code, settings)
        assert result is True

    async def test_verify_invalid_totp(self, settings: Settings) -> None:
        import pyotp

        raw_secret = pyotp.random_base32()
        encrypted = encrypt_secret(raw_secret, settings)

        mock_secret = MagicMock(spec=TOTPSecret)
        mock_secret.is_verified = True
        mock_secret.encrypted_secret = encrypted
        mock_secret.recovery_codes = "[]"

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = mock_secret
        db.execute.return_value = result_mock

        result = await verify_totp_code(db, uuid.uuid4(), "000000", settings)
        assert result is False

    async def test_verify_with_recovery_code(self, settings: Settings) -> None:
        import pyotp

        raw_secret = pyotp.random_base32()
        encrypted = encrypt_secret(raw_secret, settings)
        codes = generate_recovery_codes(4)
        hashed = _hash_recovery_codes(codes)

        mock_secret = MagicMock(spec=TOTPSecret)
        mock_secret.is_verified = True
        mock_secret.encrypted_secret = encrypted
        mock_secret.recovery_codes = hashed

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = mock_secret
        db.execute.return_value = result_mock

        result = await verify_totp_code(db, uuid.uuid4(), codes[0], settings)
        assert result is True

    async def test_no_secret_returns_false(self, settings: Settings) -> None:
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute.return_value = result_mock

        result = await verify_totp_code(db, uuid.uuid4(), "123456", settings)
        assert result is False
