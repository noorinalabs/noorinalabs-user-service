"""Tests for OAuth callback user creation/linking logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.app.models.oauth_account import OAuthAccount
from src.app.models.user import User
from src.app.services.user import (
    AccountExistsWithDifferentMethodError,
    find_or_create_oauth_user,
)


def _make_user(
    *,
    email: str = "test@example.com",
    email_verified: bool = True,
    display_name: str | None = "Test User",
    password_hash: str | None = None,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        email_verified=email_verified,
        display_name=display_name,
        password_hash=password_hash,
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


def _methods_result(providers: list[str]) -> MagicMock:
    """A db.execute(...) result whose .scalars().all() yields linked providers.

    Mirrors the `_existing_auth_methods` provider query that runs after the
    email match in step 2.
    """
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = providers
    result.scalars.return_value = scalars
    return result


class TestFindOrCreateOAuthUser:
    @pytest.mark.asyncio
    async def test_returns_existing_user_via_oauth_link(self) -> None:
        """Step 1 — same-provider re-login is UNCHANGED: matched + logged in."""
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
        # Same-provider re-login must NOT create a new link.
        db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_cross_provider_email_match_is_rejected_not_linked(self) -> None:
        """#153 — google account, github login, same verified email → REJECT.

        Previously this silently created a github OAuthAccount link on the
        existing google account. It must now raise instead, and create no link.
        """
        user = _make_user(email="existing@example.com", email_verified=True)
        db = _mock_db_session()

        # 1: no (github, uid) oauth link; 2: email match; 3: existing methods = google
        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = None
        email_result = MagicMock()
        email_result.scalar_one_or_none.return_value = user
        db.execute = AsyncMock(
            side_effect=[oauth_result, email_result, _methods_result(["google"])]
        )

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                db,
                provider="github",
                provider_account_id="gh-uid-456",
                email="existing@example.com",
                display_name="GH User",
                avatar_url=None,
            )

        assert excinfo.value.email == "existing@example.com"
        assert excinfo.value.existing_methods == ["google"]
        assert excinfo.value.primary_method == "google"
        # No link created, nothing committed.
        db.add.assert_not_called()
        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_password_account_oauth_login_is_rejected_not_linked(self) -> None:
        """#154 — password account, first google login, same email → REJECT.

        A password user attempting OAuth with a matching verified email must be
        blocked (no silent, unconsented link) and told the email is registered
        as `password`.
        """
        user = _make_user(
            email="bob@example.com",
            email_verified=True,
            password_hash="argon2:hash",
        )
        db = _mock_db_session()

        oauth_result = MagicMock()
        oauth_result.scalar_one_or_none.return_value = None
        email_result = MagicMock()
        email_result.scalar_one_or_none.return_value = user
        # No linked providers — the account is password-only.
        db.execute = AsyncMock(side_effect=[oauth_result, email_result, _methods_result([])])

        with pytest.raises(AccountExistsWithDifferentMethodError) as excinfo:
            await find_or_create_oauth_user(
                db,
                provider="google",
                provider_account_id="g-uid-789",
                email="bob@example.com",
                display_name="Bob",
                avatar_url=None,
            )

        assert excinfo.value.existing_methods == ["password"]
        assert excinfo.value.primary_method == "password"
        assert str(excinfo.value) == "bob@example.com is already registered as password"
        db.add.assert_not_called()
        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_creates_new_user_when_no_match(self) -> None:
        """Step 3 — brand-new email signup is UNCHANGED: user + link created."""
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
