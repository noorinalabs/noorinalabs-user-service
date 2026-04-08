"""Tests for email verification flow — US #8."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.dependencies import get_current_user
from src.app.main import create_app
from src.app.models.user import User
from src.app.models.verification_token import TokenType, VerificationToken
from src.app.services.verification import (
    _hash_token,
    check_rate_limit,
    confirm_verification_token,
    create_verification_token,
    invalidate_existing_tokens,
)


def _test_settings() -> Settings:
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_PRIVATE_KEY="",
        JWT_PUBLIC_KEY="",
        SMTP_HOST="localhost",
        SMTP_PORT=587,
        SMTP_FROM_EMAIL="test@noorinalabs.com",
        VERIFICATION_BASE_URL="http://localhost:3000",
    )


def _mock_user(
    email: str = "test@example.com",
    email_verified: bool = False,
) -> User:
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = email
    user.email_verified = email_verified
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


class TestSendVerification:
    async def test_send_success(self, client: AsyncClient, mock_user: User) -> None:
        with (
            patch(
                "src.app.routers.verification.check_rate_limit",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "src.app.routers.verification.create_verification_token",
                new_callable=AsyncMock,
                return_value="raw-token-abc",
            ),
            patch(
                "src.app.routers.verification.send_verification_email",
                new_callable=AsyncMock,
            ) as mock_send,
        ):
            resp = await client.post(
                "/verification/send",
                json={"email": mock_user.email},
            )
            assert resp.status_code == 200
            assert resp.json()["message"] == "Verification email sent"
            mock_send.assert_awaited_once()

    async def test_send_already_verified(self, client: AsyncClient, mock_user: User) -> None:
        mock_user.email_verified = True
        resp = await client.post(
            "/verification/send",
            json={"email": mock_user.email},
        )
        assert resp.status_code == 400
        assert "already verified" in resp.json()["detail"]

    async def test_send_email_mismatch(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/verification/send",
            json={"email": "other@example.com"},
        )
        assert resp.status_code == 400
        assert "does not match" in resp.json()["detail"]

    async def test_send_rate_limited(self, client: AsyncClient, mock_user: User) -> None:
        with patch(
            "src.app.routers.verification.check_rate_limit",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = await client.post(
                "/verification/send",
                json={"email": mock_user.email},
            )
            assert resp.status_code == 429
            assert "Rate limit" in resp.json()["detail"]


class TestConfirmVerification:
    async def test_confirm_success(self, client: AsyncClient, mock_user: User) -> None:
        with patch(
            "src.app.routers.verification.confirm_verification_token",
            new_callable=AsyncMock,
            return_value=mock_user,
        ):
            resp = await client.post(
                "/verification/confirm",
                json={"token": "valid-token"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["email_verified"] is True
            assert data["message"] == "Email verified successfully"

    async def test_confirm_invalid_token(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.verification.confirm_verification_token",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await client.post(
                "/verification/confirm",
                json={"token": "invalid-token"},
            )
            assert resp.status_code == 400
            assert "Invalid" in resp.json()["detail"]


class TestVerificationStatus:
    async def test_status_not_verified(self, client: AsyncClient, mock_user: User) -> None:
        mock_token = MagicMock(spec=VerificationToken)
        mock_token.created_at = datetime(2026, 4, 8, 12, 0, 0, tzinfo=UTC)

        with patch(
            "src.app.routers.verification.get_latest_verification_token",
            new_callable=AsyncMock,
            return_value=mock_token,
        ):
            resp = await client.get("/verification/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["email"] == mock_user.email
            assert data["email_verified"] is False
            assert data["verification_sent_at"] is not None

    async def test_status_verified(self, client: AsyncClient, mock_user: User) -> None:
        mock_user.email_verified = True
        with patch(
            "src.app.routers.verification.get_latest_verification_token",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await client.get("/verification/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["email_verified"] is True
            assert data["verification_sent_at"] is None


class TestTokenHashing:
    def test_hash_deterministic(self) -> None:
        token = "test-token-123"
        assert _hash_token(token) == _hash_token(token)

    def test_hash_different_tokens(self) -> None:
        assert _hash_token("token-a") != _hash_token("token-b")


class TestRateLimitLogic:
    async def test_within_limit(self) -> None:
        db = AsyncMock()
        settings = _test_settings()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 2
        db.execute.return_value = mock_result

        result = await check_rate_limit(db, uuid.uuid4(), settings)
        assert result is True

    async def test_at_limit(self) -> None:
        db = AsyncMock()
        settings = _test_settings()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 3
        db.execute.return_value = mock_result

        result = await check_rate_limit(db, uuid.uuid4(), settings)
        assert result is False

    async def test_over_limit(self) -> None:
        db = AsyncMock()
        settings = _test_settings()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 5
        db.execute.return_value = mock_result

        result = await check_rate_limit(db, uuid.uuid4(), settings)
        assert result is False


class TestCreateVerificationToken:
    async def test_creates_token(self) -> None:
        db = AsyncMock()
        settings = _test_settings()
        user_id = uuid.uuid4()

        with patch(
            "src.app.services.verification.invalidate_existing_tokens",
            new_callable=AsyncMock,
        ) as mock_invalidate:
            raw_token = await create_verification_token(db, user_id, settings)

        assert isinstance(raw_token, str)
        assert len(raw_token) > 20
        mock_invalidate.assert_awaited_once_with(db, user_id)
        db.add.assert_called_once()
        db.flush.assert_awaited_once()

        added_token = db.add.call_args[0][0]
        assert isinstance(added_token, VerificationToken)
        assert added_token.user_id == user_id
        assert added_token.token_type == TokenType.email_verification
        assert added_token.token_hash == _hash_token(raw_token)


class TestConfirmVerificationToken:
    async def test_confirm_valid(self) -> None:
        db = AsyncMock()
        user_id = uuid.uuid4()

        mock_vt = MagicMock(spec=VerificationToken)
        mock_vt.user_id = user_id
        mock_vt.used_at = None

        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.email_verified = False

        # First execute returns the verification token, second returns the user
        vt_result = MagicMock()
        vt_result.scalar_one_or_none.return_value = mock_vt
        user_result = MagicMock()
        user_result.scalar_one_or_none.return_value = mock_user
        db.execute.side_effect = [vt_result, user_result]

        result = await confirm_verification_token(db, "valid-token")

        assert result is mock_user
        assert mock_user.email_verified is True
        db.flush.assert_awaited_once()

    async def test_confirm_invalid(self) -> None:
        db = AsyncMock()
        vt_result = MagicMock()
        vt_result.scalar_one_or_none.return_value = None
        db.execute.return_value = vt_result

        result = await confirm_verification_token(db, "invalid-token")
        assert result is None


class TestInvalidateExistingTokens:
    async def test_invalidates(self) -> None:
        db = AsyncMock()
        user_id = uuid.uuid4()
        await invalidate_existing_tokens(db, user_id)
        db.execute.assert_awaited_once()
