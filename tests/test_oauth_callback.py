"""Tests for OAuth callback user creation/linking logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.app.models.oauth_account import OAuthAccount
from src.app.models.user import User
from src.app.services.user import find_or_create_oauth_user


def _make_user(
    *,
    email: str = "test@example.com",
    email_verified: bool = True,
    display_name: str | None = "Test User",
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        email_verified=email_verified,
        display_name=display_name,
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    return user


def _make_oauth_account(*, user_id: uuid.UUID, provider: str = "google") -> OAuthAccount:
    return OAuthAccount(
        id=uuid.uuid4(),
        user_id=user_id,
        provider=provider,
        provider_account_id="provider-uid-123",
        created_at=datetime.now(UTC),
    )


def _mock_db_session() -> AsyncMock:
    """Create a mock AsyncSession with chainable execute."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    return db


class TestFindOrCreateOAuthUser:
    @pytest.mark.asyncio
    async def test_returns_existing_user_via_oauth_link(self) -> None:
        user = _make_user()
        oauth_account = _make_oauth_account(user_id=user.id, provider="google")
        db = _mock_db_session()

        # First execute: find oauth_account; second: find user
        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = oauth_account
        user_result = MagicMock()
        user_result.scalar_one.return_value = user
        db.execute = AsyncMock(side_effect=[oauth_result, user_result])

        result = await find_or_create_oauth_user(
            db,
            provider="google",
            provider_account_id="provider-uid-123",
            email="test@example.com",
            display_name="Test User",
            avatar_url=None,
        )
        assert result.user.id == user.id
        assert result.is_new_user is False

    @pytest.mark.asyncio
    async def test_links_to_existing_user_by_verified_email(self) -> None:
        user = _make_user(email="existing@example.com", email_verified=True)
        db = _mock_db_session()

        # First execute: no oauth link; second: find user by email
        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = None
        email_result = MagicMock()
        email_result.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(side_effect=[oauth_result, email_result])

        result = await find_or_create_oauth_user(
            db,
            provider="github",
            provider_account_id="gh-uid-456",
            email="existing@example.com",
            display_name="GH User",
            avatar_url=None,
        )
        assert result.user.id == user.id
        assert result.is_new_user is False
        # Should have added the OAuth link
        db.add.assert_called()

    @pytest.mark.asyncio
    async def test_creates_new_user_when_no_match(self) -> None:
        db = _mock_db_session()

        # First execute: no oauth link; second: no email match
        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = None
        email_result = MagicMock()
        email_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(side_effect=[oauth_result, email_result])

        result = await find_or_create_oauth_user(
            db,
            provider="facebook",
            provider_account_id="fb-uid-789",
            email="newuser@example.com",
            display_name="New User",
            avatar_url="https://example.com/avatar.jpg",
        )
        assert result.is_new_user is True
        assert result.user.email == "newuser@example.com"
        assert result.user.display_name == "New User"
        assert result.user.email_verified is True
        # Should have added user + oauth link (2 calls)
        assert db.add.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_when_no_email_for_new_user(self) -> None:
        db = _mock_db_session()

        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=oauth_result)

        with pytest.raises(ValueError, match="Cannot create user without an email"):
            await find_or_create_oauth_user(
                db,
                provider="apple",
                provider_account_id="apple-uid-000",
                email=None,
                display_name=None,
                avatar_url=None,
            )
