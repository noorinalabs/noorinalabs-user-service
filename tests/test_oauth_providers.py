"""Tests for OAuth provider URL generation and code exchange with mocked httpx."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.app.config import Settings
from src.app.services.oauth import (
    AppleOAuthProvider,
    FacebookOAuthProvider,
    GitHubOAuthProvider,
    GoogleOAuthProvider,
    generate_pkce_pair,
    get_oauth_provider,
)


def _make_settings(**overrides: str) -> Settings:
    """Create a Settings instance with OAuth defaults filled in."""
    defaults = {
        "AUTH_GOOGLE_CLIENT_ID": "google-client-id",
        "AUTH_GOOGLE_CLIENT_SECRET": "google-secret",
        "AUTH_GITHUB_CLIENT_ID": "github-client-id",
        "AUTH_GITHUB_CLIENT_SECRET": "github-secret",
        "AUTH_APPLE_CLIENT_ID": "apple-client-id",
        "AUTH_APPLE_TEAM_ID": "TEAMID",
        "AUTH_APPLE_KEY_ID": "KEYID",
        "AUTH_APPLE_PRIVATE_KEY": "fake-private-key",
        "AUTH_FACEBOOK_APP_ID": "fb-app-id",
        "AUTH_FACEBOOK_APP_SECRET": "fb-secret",
        "AUTH_OAUTH_REDIRECT_BASE_URL": "http://localhost:8000",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


class TestPKCE:
    def test_generate_pkce_pair_returns_verifier_and_challenge(self) -> None:
        verifier, challenge = generate_pkce_pair()
        assert len(verifier) > 40
        assert len(challenge) > 20
        assert verifier != challenge

    def test_pkce_pairs_are_unique(self) -> None:
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        assert pair1[0] != pair2[0]


class TestGetOAuthProvider:
    def test_returns_google_provider(self) -> None:
        provider = get_oauth_provider("google", _make_settings())
        assert isinstance(provider, GoogleOAuthProvider)

    def test_returns_github_provider(self) -> None:
        provider = get_oauth_provider("github", _make_settings())
        assert isinstance(provider, GitHubOAuthProvider)

    def test_returns_apple_provider(self) -> None:
        provider = get_oauth_provider("apple", _make_settings())
        assert isinstance(provider, AppleOAuthProvider)

    def test_returns_facebook_provider(self) -> None:
        provider = get_oauth_provider("facebook", _make_settings())
        assert isinstance(provider, FacebookOAuthProvider)

    def test_raises_for_unknown_provider(self) -> None:
        with pytest.raises(ValueError, match="Unsupported OAuth provider"):
            get_oauth_provider("twitter", _make_settings())


class TestGoogleProvider:
    def test_authorization_url(self) -> None:
        provider = GoogleOAuthProvider(_make_settings())
        url = provider.get_authorization_url(
            state="test-state",
            code_challenge="test-challenge",
            redirect_uri="http://localhost:8000/auth/oauth/google/callback",
        )
        assert "accounts.google.com" in url
        assert "client_id=google-client-id" in url
        assert "state=test-state" in url
        assert "code_challenge=test-challenge" in url
        assert "scope=openid+email+profile" in url

    @pytest.mark.asyncio
    async def test_exchange_code(self) -> None:
        provider = GoogleOAuthProvider(_make_settings())
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "gtoken", "id_token": "gid"}
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await provider.exchange_code("code123", "verifier123", "http://redir")
            assert result["access_token"] == "gtoken"
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_info(self) -> None:
        provider = GoogleOAuthProvider(_make_settings())
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "sub": "google-uid-123",
            "email": "user@example.com",
            "name": "Test User",
            "picture": "https://example.com/avatar.jpg",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            info = await provider.get_user_info("gtoken")
            assert info.provider == "google"
            assert info.provider_account_id == "google-uid-123"
            assert info.email == "user@example.com"
            assert info.display_name == "Test User"


class TestGitHubProvider:
    def test_authorization_url(self) -> None:
        provider = GitHubOAuthProvider(_make_settings())
        url = provider.get_authorization_url(
            state="gh-state",
            code_challenge="gh-challenge",
            redirect_uri="http://localhost:8000/auth/oauth/github/callback",
        )
        assert "github.com/login/oauth/authorize" in url
        assert "client_id=github-client-id" in url
        assert "scope=user%3Aemail" in url

    @pytest.mark.asyncio
    async def test_get_user_info_with_email_in_user_response(self) -> None:
        provider = GitHubOAuthProvider(_make_settings())
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": 12345,
            "email": "ghuser@example.com",
            "name": "GH User",
            "login": "ghuser",
            "avatar_url": "https://github.com/avatar.jpg",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            info = await provider.get_user_info("ghtoken")
            assert info.provider == "github"
            assert info.provider_account_id == "12345"
            assert info.email == "ghuser@example.com"

    @pytest.mark.asyncio
    async def test_get_user_info_falls_back_to_emails_api(self) -> None:
        provider = GitHubOAuthProvider(_make_settings())

        user_response = MagicMock()
        user_response.json.return_value = {
            "id": 12345,
            "email": None,
            "name": "GH User",
            "login": "ghuser",
            "avatar_url": "https://github.com/avatar.jpg",
        }
        user_response.raise_for_status = MagicMock()

        emails_response = MagicMock()
        emails_response.json.return_value = [
            {"email": "other@example.com", "primary": False, "verified": True},
            {"email": "primary@example.com", "primary": True, "verified": True},
        ]
        emails_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=[user_response, emails_response])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            info = await provider.get_user_info("ghtoken")
            assert info.email == "primary@example.com"


class TestAppleProvider:
    def test_authorization_url(self) -> None:
        provider = AppleOAuthProvider(_make_settings())
        url = provider.get_authorization_url(
            state="apple-state",
            code_challenge="apple-challenge",
            redirect_uri="http://localhost:8000/auth/oauth/apple/callback",
        )
        assert "appleid.apple.com/auth/authorize" in url
        assert "scope=email+name" in url
        assert "response_mode=form_post" in url

    @pytest.mark.asyncio
    async def test_get_user_info_from_id_token(self) -> None:
        provider = AppleOAuthProvider(_make_settings())

        with patch("jose.jwt.get_unverified_claims") as mock_get_claims:
            mock_jwt = MagicMock()
            mock_jwt.get_unverified_claims = mock_get_claims
            mock_get_claims.return_value = {
                "sub": "apple-uid-001",
                "email": "apple@example.com",
            }
            info = await provider.get_user_info("fake-id-token")
            assert info.provider == "apple"
            assert info.provider_account_id == "apple-uid-001"
            assert info.email == "apple@example.com"
            assert info.display_name is None


class TestFacebookProvider:
    def test_authorization_url(self) -> None:
        provider = FacebookOAuthProvider(_make_settings())
        url = provider.get_authorization_url(
            state="fb-state",
            code_challenge="fb-challenge",
            redirect_uri="http://localhost:8000/auth/oauth/facebook/callback",
        )
        assert "facebook.com" in url
        assert "client_id=fb-app-id" in url
        assert "scope=email" in url

    @pytest.mark.asyncio
    async def test_get_user_info(self) -> None:
        provider = FacebookOAuthProvider(_make_settings())
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "fb-uid-999",
            "name": "FB User",
            "email": "fbuser@example.com",
            "picture": {"data": {"url": "https://fb.com/pic.jpg", "is_silhouette": False}},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            info = await provider.get_user_info("fbtoken")
            assert info.provider == "facebook"
            assert info.provider_account_id == "fb-uid-999"
            assert info.email == "fbuser@example.com"
            assert info.avatar_url == "https://fb.com/pic.jpg"

    @pytest.mark.asyncio
    async def test_get_user_info_skips_silhouette_avatar(self) -> None:
        provider = FacebookOAuthProvider(_make_settings())
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "fb-uid-999",
            "name": "FB User",
            "email": "fbuser@example.com",
            "picture": {"data": {"url": "https://fb.com/default.jpg", "is_silhouette": True}},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            info = await provider.get_user_info("fbtoken")
            assert info.avatar_url is None
