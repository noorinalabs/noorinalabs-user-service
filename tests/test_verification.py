"""Tests for email verification flow — US #8.

Uses SQLite-backed integration tests matching codebase convention. Shared
fixtures (RSA keygen, token helpers, db_engine/db_session/client) live in
tests/conftest.py — see US#56. This module overrides the `settings` fixture
to add the SMTP + verification config the verification service needs, and
declares its own `test_user`/`verified_user` (it does not use roles).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings
from src.app.models.user import User
from src.app.models.verification_token import TokenType
from src.app.services.verification import (
    check_rate_limit,
    confirm_verification_token,
    create_verification_token,
    get_latest_verification_token,
    invalidate_existing_tokens,
)
from src.app.utils.crypto import hash_token
from tests.conftest import TEST_PRIVATE_PEM, build_test_settings
from tests.conftest import auth_header as _auth_header


@pytest.fixture
def settings() -> Settings:
    """Override the conftest `settings` fixture with SMTP + verification config."""
    return build_test_settings(
        JWT_PRIVATE_KEY=TEST_PRIVATE_PEM,
        SMTP_HOST="localhost",
        SMTP_PORT=587,
        SMTP_FROM_EMAIL="test@noorinalabs.com",
        VERIFICATION_BASE_URL="http://localhost:3000",
        VERIFICATION_RATE_LIMIT_MAX=3,
        VERIFICATION_RATE_LIMIT_WINDOW_MINUTES=60,
        VERIFICATION_TOKEN_EXPIRE_HOURS=24,
    )


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        email="verify@example.com",
        display_name="Test User",
        email_verified=False,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture
async def verified_user(db_session: AsyncSession) -> User:
    user = User(
        email="verified@example.com",
        display_name="Verified User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    return user


# --- Service-layer integration tests ---


class TestCheckRateLimit:
    async def test_within_limit(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        for _ in range(2):
            await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        result = await check_rate_limit(db_session, test_user.id, settings)
        assert result is True

    async def test_at_limit(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        for _ in range(3):
            await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        result = await check_rate_limit(db_session, test_user.id, settings)
        assert result is False


class TestCreateVerificationToken:
    async def test_creates_token(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        raw_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        assert isinstance(raw_token, str)
        assert len(raw_token) > 20

        latest = await get_latest_verification_token(db_session, test_user.id)
        assert latest is not None
        assert latest.token_hash == hash_token(raw_token)
        assert latest.token_type == TokenType.email_verification
        assert latest.used_at is None

    async def test_resend_invalidates_old(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        old_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        _new_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        result = await confirm_verification_token(db_session, old_token)
        assert result is None


class TestConfirmVerificationToken:
    async def test_confirm_valid(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        raw_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        user = await confirm_verification_token(db_session, raw_token)
        await db_session.commit()

        assert user is not None
        assert user.email_verified is True

    async def test_confirm_invalid_token(self, db_session: AsyncSession) -> None:
        result = await confirm_verification_token(db_session, "nonexistent-token")
        assert result is None

    async def test_confirm_expired_token(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        raw_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        latest = await get_latest_verification_token(db_session, test_user.id)
        assert latest is not None
        latest.expires_at = datetime.now(UTC) - timedelta(hours=1)
        await db_session.commit()

        result = await confirm_verification_token(db_session, raw_token)
        assert result is None

    async def test_confirm_already_used(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        raw_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        user = await confirm_verification_token(db_session, raw_token)
        await db_session.commit()
        assert user is not None

        result = await confirm_verification_token(db_session, raw_token)
        assert result is None


class TestInvalidateExistingTokens:
    async def test_invalidates(
        self, db_session: AsyncSession, test_user: User, settings: Settings
    ) -> None:
        raw_token = await create_verification_token(db_session, test_user.id, settings)
        await db_session.commit()

        await invalidate_existing_tokens(db_session, test_user.id)
        await db_session.commit()

        result = await confirm_verification_token(db_session, raw_token)
        assert result is None


class TestTokenHashing:
    def test_hash_deterministic(self) -> None:
        token = "test-token-123"
        assert hash_token(token) == hash_token(token)

    def test_hash_different_tokens(self) -> None:
        assert hash_token("token-a") != hash_token("token-b")


# --- Endpoint integration tests ---


class TestSendEndpoint:
    async def test_send_success(self, client: AsyncClient, test_user: User) -> None:
        with patch(
            "src.app.routers.verification.send_verification_email",
            new_callable=AsyncMock,
        ) as mock_send:
            resp = await client.post(
                "/api/v1/verification/send",
                json={"email": test_user.email},
                headers=_auth_header(test_user),
            )
            assert resp.status_code == 200
            assert resp.json()["message"] == "Verification email sent"
            mock_send.assert_awaited_once()

    async def test_send_already_verified(self, client: AsyncClient, verified_user: User) -> None:
        resp = await client.post(
            "/api/v1/verification/send",
            json={"email": verified_user.email},
            headers=_auth_header(verified_user),
        )
        assert resp.status_code == 400
        assert "already verified" in resp.json()["detail"]

    async def test_send_email_mismatch(self, client: AsyncClient, test_user: User) -> None:
        resp = await client.post(
            "/api/v1/verification/send",
            json={"email": "other@example.com"},
            headers=_auth_header(test_user),
        )
        assert resp.status_code == 400
        assert "does not match" in resp.json()["detail"]

    async def test_send_rate_limited(self, client: AsyncClient, test_user: User) -> None:
        for _ in range(3):
            with patch(
                "src.app.routers.verification.send_verification_email",
                new_callable=AsyncMock,
            ):
                await client.post(
                    "/api/v1/verification/send",
                    json={"email": test_user.email},
                    headers=_auth_header(test_user),
                )

        resp = await client.post(
            "/api/v1/verification/send",
            json={"email": test_user.email},
            headers=_auth_header(test_user),
        )
        assert resp.status_code == 429
        assert "Rate limit" in resp.json()["detail"]


class TestConfirmEndpoint:
    async def test_confirm_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/verification/confirm",
            json={"token": "invalid-token"},
        )
        assert resp.status_code == 400
        assert "Invalid" in resp.json()["detail"]


class TestStatusEndpoint:
    async def test_status_not_verified(self, client: AsyncClient, test_user: User) -> None:
        resp = await client.get(
            "/api/v1/verification/status",
            headers=_auth_header(test_user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == test_user.email
        assert data["email_verified"] is False

    async def test_status_verified(self, client: AsyncClient, verified_user: User) -> None:
        resp = await client.get(
            "/api/v1/verification/status",
            headers=_auth_header(verified_user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_verified"] is True
