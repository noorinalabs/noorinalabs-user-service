"""OAuth provider implementations — Google, GitHub, Apple, Facebook."""

from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx

from src.app.config import Settings
from src.app.schemas.auth import OAuthUserInfo


class OAuthProvider(StrEnum):
    GOOGLE = "google"
    GITHUB = "github"
    APPLE = "apple"
    FACEBOOK = "facebook"


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _maybe_override(url: str, override: str | None) -> str:
    """Rewrite the scheme+host of `url` to match `override` when set.

    Path, query, and fragment are preserved so the fake provider only needs to
    mirror the real provider's paths. No-op when `override` is None/empty.
    """
    if not override:
        return url
    parsed = urlparse(url)
    override_parsed = urlparse(override)
    return parsed._replace(
        scheme=override_parsed.scheme,
        netloc=override_parsed.netloc,
    ).geturl()


class BaseOAuthProvider(ABC):
    """Base class for OAuth provider implementations."""

    provider: OAuthProvider

    @abstractmethod
    def __init__(self, settings: Settings) -> None: ...

    @abstractmethod
    def get_authorization_url(self, state: str, code_challenge: str, redirect_uri: str) -> str:
        """Build the provider's authorization URL with PKCE."""

    @abstractmethod
    async def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        """Exchange an authorization code for provider tokens."""

    @abstractmethod
    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch and normalize user info from the provider."""


class GoogleOAuthProvider(BaseOAuthProvider):
    """Google OpenID Connect provider."""

    provider = OAuthProvider.GOOGLE

    def __init__(self, settings: Settings) -> None:
        self.client_id = settings.AUTH_GOOGLE_CLIENT_ID
        self.client_secret = settings.AUTH_GOOGLE_CLIENT_SECRET
        self.base_url_override = settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE

    def get_authorization_url(self, state: str, code_challenge: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
        }
        url = f"https://accounts.google.com/o/oauth2/v2/auth?{_urlencode(params)}"
        return _maybe_override(url, self.base_url_override)

    async def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                _maybe_override("https://oauth2.googleapis.com/token", self.base_url_override),
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                _maybe_override(
                    "https://www.googleapis.com/oauth2/v3/userinfo", self.base_url_override
                ),
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()
        return OAuthUserInfo(
            provider=self.provider.value,
            provider_account_id=data["sub"],
            email=data.get("email"),
            display_name=data.get("name"),
            avatar_url=data.get("picture"),
        )


class GitHubOAuthProvider(BaseOAuthProvider):
    """GitHub OAuth 2.0 provider."""

    provider = OAuthProvider.GITHUB

    def __init__(self, settings: Settings) -> None:
        self.client_id = settings.AUTH_GITHUB_CLIENT_ID
        self.client_secret = settings.AUTH_GITHUB_CLIENT_SECRET
        self.base_url_override = settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE

    def get_authorization_url(self, state: str, code_challenge: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "user:email",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        url = f"https://github.com/login/oauth/authorize?{_urlencode(params)}"
        return _maybe_override(url, self.base_url_override)

    async def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                _maybe_override(
                    "https://github.com/login/oauth/access_token", self.base_url_override
                ),
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "code_verifier": code_verifier,
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            user_resp = await client.get(
                _maybe_override("https://api.github.com/user", self.base_url_override),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            user_resp.raise_for_status()
            user_data = user_resp.json()

            # GitHub may not include email in user response — fetch from emails API
            email = user_data.get("email")
            if not email:
                email_resp = await client.get(
                    _maybe_override("https://api.github.com/user/emails", self.base_url_override),
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
                email_resp.raise_for_status()
                emails = email_resp.json()
                for e in emails:
                    if e.get("primary") and e.get("verified"):
                        email = e["email"]
                        break

        return OAuthUserInfo(
            provider=self.provider.value,
            provider_account_id=str(user_data["id"]),
            email=email,
            display_name=user_data.get("name") or user_data.get("login"),
            avatar_url=user_data.get("avatar_url"),
        )


class AppleOAuthProvider(BaseOAuthProvider):
    """Sign in with Apple provider."""

    provider = OAuthProvider.APPLE

    def __init__(self, settings: Settings) -> None:
        self.client_id = settings.AUTH_APPLE_CLIENT_ID
        self.team_id = settings.AUTH_APPLE_TEAM_ID
        self.key_id = settings.AUTH_APPLE_KEY_ID
        self.private_key = settings.AUTH_APPLE_PRIVATE_KEY
        self.base_url_override = settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE

    def _generate_client_secret(self) -> str:
        """Generate a short-lived JWT client secret for Apple."""
        import time

        from jose import jwt as jose_jwt

        now = int(time.time())
        payload = {
            "iss": self.team_id,
            "iat": now,
            "exp": now + 300,
            "aud": "https://appleid.apple.com",
            "sub": self.client_id,
        }
        return jose_jwt.encode(
            payload,
            self.private_key,
            algorithm="ES256",
            headers={"kid": self.key_id},
        )

    def get_authorization_url(self, state: str, code_challenge: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "email name",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_mode": "form_post",
        }
        url = f"https://appleid.apple.com/auth/authorize?{_urlencode(params)}"
        return _maybe_override(url, self.base_url_override)

    async def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        client_secret = self._generate_client_secret()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                _maybe_override("https://appleid.apple.com/auth/token", self.base_url_override),
                data={
                    "client_id": self.client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Decode Apple's id_token to extract user info.

        Apple does not have a userinfo endpoint — user data is in the id_token JWT.
        The access_token parameter here should be the id_token from the token response.
        Signature is verified against Apple's published JWKS.
        """
        from jose import jwt as jose_jwt

        # Fetch Apple's public keys and verify the id_token signature
        async with httpx.AsyncClient() as client:
            jwks_resp = await client.get(
                _maybe_override("https://appleid.apple.com/auth/keys", self.base_url_override)
            )
            jwks_resp.raise_for_status()
            apple_jwks = jwks_resp.json()

        claims = jose_jwt.decode(
            access_token,
            apple_jwks,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer="https://appleid.apple.com",
        )
        return OAuthUserInfo(
            provider=self.provider.value,
            provider_account_id=claims["sub"],
            email=claims.get("email"),
            display_name=None,  # Apple only sends name on first auth
            avatar_url=None,
        )


class FacebookOAuthProvider(BaseOAuthProvider):
    """Facebook OAuth 2.0 provider."""

    provider = OAuthProvider.FACEBOOK

    def __init__(self, settings: Settings) -> None:
        self.app_id = settings.AUTH_FACEBOOK_APP_ID
        self.app_secret = settings.AUTH_FACEBOOK_APP_SECRET
        self.base_url_override = settings.OAUTH_PROVIDER_BASE_URL_OVERRIDE

    def get_authorization_url(self, state: str, code_challenge: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.app_id,
            "redirect_uri": redirect_uri,
            "scope": "email,public_profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }
        url = f"https://www.facebook.com/v19.0/dialog/oauth?{_urlencode(params)}"
        return _maybe_override(url, self.base_url_override)

    async def exchange_code(
        self, code: str, code_verifier: str, redirect_uri: str
    ) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                _maybe_override(
                    "https://graph.facebook.com/v19.0/oauth/access_token",
                    self.base_url_override,
                ),
                params={
                    "client_id": self.app_id,
                    "client_secret": self.app_secret,
                    "code": code,
                    "code_verifier": code_verifier,
                    "redirect_uri": redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                _maybe_override("https://graph.facebook.com/v19.0/me", self.base_url_override),
                params={
                    "fields": "id,name,email,picture.type(large)",
                    "access_token": access_token,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        picture_url = None
        picture_data = data.get("picture", {}).get("data", {})
        if picture_data and not picture_data.get("is_silhouette"):
            picture_url = picture_data.get("url")

        return OAuthUserInfo(
            provider=self.provider.value,
            provider_account_id=data["id"],
            email=data.get("email"),
            display_name=data.get("name"),
            avatar_url=picture_url,
        )


def get_oauth_provider(provider_name: str, settings: Settings) -> BaseOAuthProvider:
    """Factory function to get the appropriate OAuth provider."""
    providers: dict[str, type[BaseOAuthProvider]] = {
        OAuthProvider.GOOGLE.value: GoogleOAuthProvider,
        OAuthProvider.GITHUB.value: GitHubOAuthProvider,
        OAuthProvider.APPLE.value: AppleOAuthProvider,
        OAuthProvider.FACEBOOK.value: FacebookOAuthProvider,
    }
    provider_cls = providers.get(provider_name)
    if provider_cls is None:
        msg = f"Unsupported OAuth provider: {provider_name}"
        raise ValueError(msg)
    return provider_cls(settings)


def _urlencode(params: dict[str, str]) -> str:
    """URL-encode query parameters."""
    from urllib.parse import urlencode

    return urlencode(params)
