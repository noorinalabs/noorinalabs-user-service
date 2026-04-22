"""Tests for OAUTH_PROVIDER_BASE_URL_OVERRIDE — integration-testing hook.

Covers the `_maybe_override` helper, the Settings validator, and each provider's
URL surfaces (authorize URL, token endpoint, userinfo endpoint, JWKS).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest
from pydantic import ValidationError

from src.app.config import Settings
from src.app.services.oauth import (
    AppleOAuthProvider,
    FacebookOAuthProvider,
    GitHubOAuthProvider,
    GoogleOAuthProvider,
    _maybe_override,
)


def _make_settings(**overrides: str | None) -> Settings:
    """Create a Settings instance with OAuth defaults filled in."""
    defaults: dict[str, str | None] = {
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


class TestMaybeOverrideHelper:
    def test_returns_unchanged_when_override_none(self) -> None:
        assert (
            _maybe_override("https://accounts.google.com/o/oauth2/v2/auth", None)
            == "https://accounts.google.com/o/oauth2/v2/auth"
        )

    def test_returns_unchanged_when_override_empty_string(self) -> None:
        assert (
            _maybe_override("https://accounts.google.com/o/oauth2/v2/auth", "")
            == "https://accounts.google.com/o/oauth2/v2/auth"
        )

    def test_rewrites_host_preserves_path(self) -> None:
        rewritten = _maybe_override(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "http://fake_oauth:8080",
        )
        parsed = urlparse(rewritten)
        assert parsed.scheme == "http"
        assert parsed.netloc == "fake_oauth:8080"
        assert parsed.path == "/o/oauth2/v2/auth"

    def test_preserves_query_string(self) -> None:
        rewritten = _maybe_override(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&state=xyz",
            "http://fake_oauth:8080",
        )
        parsed = urlparse(rewritten)
        assert parsed.netloc == "fake_oauth:8080"
        assert parsed.path == "/o/oauth2/v2/auth"
        assert "client_id=abc" in parsed.query
        assert "state=xyz" in parsed.query

    def test_scheme_follows_override(self) -> None:
        # Production URL is https; override specifies http → scheme becomes http
        rewritten = _maybe_override(
            "https://oauth2.googleapis.com/token",
            "http://fake:9999",
        )
        assert rewritten.startswith("http://fake:9999/")

        # And vice versa
        rewritten = _maybe_override(
            "http://example.com/token",
            "https://secure.example:443",
        )
        assert rewritten.startswith("https://secure.example:443/")


class TestSettingsValidator:
    def test_override_unset_is_none(self) -> None:
        settings = _make_settings()
        assert settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE is None

    def test_override_empty_string_becomes_none(self) -> None:
        settings = _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="")
        assert settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE is None

    def test_override_valid_value_accepted(self) -> None:
        settings = _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake_oauth:8080")
        assert settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE == "http://fake_oauth:8080"

    def test_override_https_scheme_accepted(self) -> None:
        settings = _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="https://fake.example.com")
        assert settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE == "https://fake.example.com"

    def test_override_missing_scheme_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="fake_oauth:8080")
        assert "scheme and host" in str(exc.value)

    def test_override_bare_host_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="fake_oauth")
        assert "scheme and host" in str(exc.value)

    def test_override_scheme_only_raises(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://")
        assert "scheme and host" in str(exc.value)


class TestGoogleOverride:
    def test_authorization_url_override_unset(self) -> None:
        provider = GoogleOAuthProvider(_make_settings())
        url = provider.get_authorization_url("s", "c", "http://localhost/cb")
        assert urlparse(url).netloc == "accounts.google.com"

    def test_authorization_url_override_set(self) -> None:
        provider = GoogleOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        url = provider.get_authorization_url("s", "c", "http://localhost/cb")
        parsed = urlparse(url)
        assert parsed.scheme == "http"
        assert parsed.netloc == "fake:8080"
        assert parsed.path == "/o/oauth2/v2/auth"

    @pytest.mark.asyncio
    async def test_exchange_code_override_set_rewrites_token_host(self) -> None:
        provider = GoogleOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "x"}
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.exchange_code("code", "verifier", "http://localhost/cb")

            called_url = mock_client.post.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/token"

    @pytest.mark.asyncio
    async def test_get_user_info_override_set_rewrites_userinfo_host(self) -> None:
        provider = GoogleOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {"sub": "u1", "email": "e@example.com"}
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.get_user_info("token")

            called_url = mock_client.get.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/oauth2/v3/userinfo"


class TestGitHubOverride:
    def test_authorization_url_override_set(self) -> None:
        provider = GitHubOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        url = provider.get_authorization_url("s", "c", "http://localhost/cb")
        parsed = urlparse(url)
        assert parsed.netloc == "fake:8080"
        assert parsed.path == "/login/oauth/authorize"

    @pytest.mark.asyncio
    async def test_exchange_code_override_set(self) -> None:
        provider = GitHubOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "x"}
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.exchange_code("code", "verifier", "http://localhost/cb")

            called_url = mock_client.post.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/login/oauth/access_token"

    @pytest.mark.asyncio
    async def test_get_user_info_override_set_rewrites_user_and_emails(self) -> None:
        provider = GitHubOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        user_resp = MagicMock()
        user_resp.json.return_value = {
            "id": 1,
            "email": None,
            "name": "N",
            "login": "l",
            "avatar_url": None,
        }
        user_resp.raise_for_status = MagicMock()

        emails_resp = MagicMock()
        emails_resp.json.return_value = [
            {"email": "p@example.com", "primary": True, "verified": True},
        ]
        emails_resp.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=[user_resp, emails_resp])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.get_user_info("token")

            user_url = mock_client.get.call_args_list[0][0][0]
            emails_url = mock_client.get.call_args_list[1][0][0]
            assert urlparse(user_url).netloc == "fake:8080"
            assert urlparse(user_url).path == "/user"
            assert urlparse(emails_url).netloc == "fake:8080"
            assert urlparse(emails_url).path == "/user/emails"


class TestAppleOverride:
    def test_authorization_url_override_set(self) -> None:
        provider = AppleOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        url = provider.get_authorization_url("s", "c", "http://localhost/cb")
        parsed = urlparse(url)
        assert parsed.netloc == "fake:8080"
        assert parsed.path == "/auth/authorize"

    @pytest.mark.asyncio
    async def test_get_user_info_rewrites_jwks_host(self) -> None:
        provider = AppleOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        jwks_resp = MagicMock()
        jwks_resp.json.return_value = {"keys": [{"kty": "RSA", "kid": "t"}]}
        jwks_resp.raise_for_status = MagicMock()

        with (
            patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls,
            patch("jose.jwt.decode") as mock_decode,
        ):
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=jwks_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client
            mock_decode.return_value = {"sub": "a1", "email": "a@example.com"}

            await provider.get_user_info("fake-id-token")

            called_url = mock_client.get.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/auth/keys"


class TestFacebookOverride:
    def test_authorization_url_override_set(self) -> None:
        provider = FacebookOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        url = provider.get_authorization_url("s", "c", "http://localhost/cb")
        parsed = urlparse(url)
        assert parsed.netloc == "fake:8080"
        assert parsed.path == "/v19.0/dialog/oauth"

    @pytest.mark.asyncio
    async def test_exchange_code_override_set(self) -> None:
        provider = FacebookOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "x"}
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.exchange_code("code", "verifier", "http://localhost/cb")

            called_url = mock_client.get.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/v19.0/oauth/access_token"

    @pytest.mark.asyncio
    async def test_get_user_info_override_set(self) -> None:
        provider = FacebookOAuthProvider(
            _make_settings(OAUTH_PROVIDER_BASE_URL_OVERRIDE="http://fake:8080")
        )
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "f1",
            "name": "F",
            "email": "f@example.com",
            "picture": {"data": {"url": "", "is_silhouette": True}},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("src.app.services.oauth.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await provider.get_user_info("token")

            called_url = mock_client.get.call_args[0][0]
            parsed = urlparse(called_url)
            assert parsed.netloc == "fake:8080"
            assert parsed.path == "/v19.0/me"
