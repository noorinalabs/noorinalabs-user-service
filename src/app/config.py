from functools import lru_cache
from typing import Self
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings

_ALLOWED_OVERRIDE_SCHEMES = frozenset({"http", "https"})
_PROD_LIKE_ENVIRONMENTS = frozenset({"production", "staging"})
_ALLOWED_ENVIRONMENTS = frozenset({"development", "test", "staging", "production"})


def _host_of(url: str) -> str | None:
    """Return the lowercased hostname of an absolute URL, or None if it has no host.

    Used to build the AUTH_OAUTH_POST_LOGIN_URL allowlist from other URL settings.
    """
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else None


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Deployment environment — gates security-sensitive settings
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str = (
        "postgresql+asyncpg://user_service:user_service_dev@localhost:5433/user_service"
    )

    # Redis
    REDIS_URL: str = "redis://localhost:6380/0"

    # JWT (RS256)
    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Auth
    AUTH_PASSWORD_MIN_LENGTH: int = 8
    AUTH_MAX_LOGIN_ATTEMPTS: int = 5
    AUTH_LOCKOUT_DURATION_MINUTES: int = 15
    # Per-IP rate limiting on auth endpoints (token issue/refresh/validate, OAuth
    # callback). Backed by Redis; uses AUTH_MAX_LOGIN_ATTEMPTS as the per-window
    # limit and AUTH_LOCKOUT_DURATION_MINUTES as the window length. Disable only
    # for local dev / tests where the speed-bump gets in the way.
    AUTH_RATE_LIMIT_ENABLED: bool = True

    # OAuth — Google
    AUTH_GOOGLE_CLIENT_ID: str = ""
    AUTH_GOOGLE_CLIENT_SECRET: str = ""

    # OAuth — GitHub
    AUTH_GITHUB_CLIENT_ID: str = ""
    AUTH_GITHUB_CLIENT_SECRET: str = ""

    # OAuth — Apple
    AUTH_APPLE_CLIENT_ID: str = ""
    AUTH_APPLE_TEAM_ID: str = ""
    AUTH_APPLE_KEY_ID: str = ""
    AUTH_APPLE_PRIVATE_KEY: str = ""

    # OAuth — Facebook
    AUTH_FACEBOOK_APP_ID: str = ""
    AUTH_FACEBOOK_APP_SECRET: str = ""

    # Email verification
    VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    VERIFICATION_RATE_LIMIT_MAX: int = 3
    VERIFICATION_RATE_LIMIT_WINDOW_MINUTES: int = 60
    VERIFICATION_BASE_URL: str = "http://localhost:3000"

    # SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@noorinalabs.com"
    SMTP_FROM_NAME: str = "NoorinALabs"
    SMTP_START_TLS: bool = True

    # 2FA / TOTP
    TOTP_ISSUER_NAME: str = "NoorinALabs"
    TOTP_ENCRYPTION_KEY: str = ""  # Fernet key for encrypting TOTP secrets at rest
    TOTP_RECOVERY_CODE_COUNT: int = 8

    # Webhook
    WEBHOOK_SIGNING_SECRET: str = ""

    # OAuth — Redirect base URL
    AUTH_OAUTH_REDIRECT_BASE_URL: str = "http://localhost:8000"

    # OAuth — Provider base URL override (integration testing only)
    # When set, overrides provider OAuth endpoint hosts for integration testing.
    # Format: scheme+host (e.g., "http://fake_oauth:8080"). Rewrites authorize-URL,
    # token-endpoint, and userinfo-endpoint hosts to this base — paths are preserved.
    # Leave unset in production.
    OAUTH_PROVIDER_BASE_URL_OVERRIDE: str | None = None

    # OAuth — Server-side flow (GET callback)
    # BASE path for the frontend destination after successful OAuth. The handler
    # always appends `/{provider}` to match the frontend route
    # `auth/callback/:provider` (required path param). Final shape:
    #   {AUTH_OAUTH_POST_LOGIN_URL}/{provider}?token=...&is_new_user=0|1
    # or on failure:
    #   {AUTH_OAUTH_POST_LOGIN_URL}/{provider}?error=<code>
    # May be absolute or same-origin relative. Do NOT include `/{provider}` — appended.
    AUTH_OAUTH_POST_LOGIN_URL: str = "/auth/callback"
    # TTL for state/code_verifier entries in Redis (upper bound on OAuth round-trip)
    AUTH_OAUTH_STATE_TTL_SECONDS: int = 600
    # Whether to set the refresh-token cookie with Secure=True. Must be True in prod;
    # set to False in local HTTP dev.
    AUTH_OAUTH_REFRESH_COOKIE_SECURE: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("ENVIRONMENT")
    @classmethod
    def _validate_environment(cls, v: str) -> str:
        if v not in _ALLOWED_ENVIRONMENTS:
            msg = f"ENVIRONMENT must be one of {sorted(_ALLOWED_ENVIRONMENTS)}, got: {v!r}"
            raise ValueError(msg)
        return v

    @field_validator("OAUTH_PROVIDER_BASE_URL_OVERRIDE")
    @classmethod
    def _validate_oauth_provider_base_url_override(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            msg = (
                "OAUTH_PROVIDER_BASE_URL_OVERRIDE must include scheme and host "
                f"(e.g., 'http://fake_oauth:8080'), got: {v!r}"
            )
            raise ValueError(msg)
        if parsed.scheme not in _ALLOWED_OVERRIDE_SCHEMES:
            msg = (
                "OAUTH_PROVIDER_BASE_URL_OVERRIDE scheme must be one of "
                f"{sorted(_ALLOWED_OVERRIDE_SCHEMES)}, got: {parsed.scheme!r}"
            )
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def _guard_oauth_provider_base_url_override(self) -> Self:
        override = self.OAUTH_PROVIDER_BASE_URL_OVERRIDE
        if override is None:
            return self
        if self.ENVIRONMENT in _PROD_LIKE_ENVIRONMENTS:
            msg = (
                "OAUTH_PROVIDER_BASE_URL_OVERRIDE must not be set in "
                "production/staging environments"
            )
            raise ValueError(msg)
        if self.ENVIRONMENT != "test" and urlparse(override).scheme != "https":
            msg = (
                "OAUTH_PROVIDER_BASE_URL_OVERRIDE must use https:// outside "
                "ENVIRONMENT=test (no HTTP downgrade)"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_oauth_post_login_url(self) -> Self:
        """Open-redirect hardening for AUTH_OAUTH_POST_LOGIN_URL (#69).

        The OAuth callback redirects the browser — with a freshly minted access
        token attached — to this URL. It is operator-controlled (an env var, no
        `?next=` override) so it is not an exploitable open redirect today, but a
        misconfigured or compromised deploy config should not be able to divert
        token-bearing traffic to an attacker host. Validation runs at boot so a
        bad value fails fast rather than at request time.

        Accepted:
          - a same-origin relative URL starting with a single `/`, OR
          - an absolute URL whose host is in the allowlist derived from
            AUTH_OAUTH_REDIRECT_BASE_URL + CORS_ORIGINS.

        Rejected everywhere: `javascript:` / `data:` schemes, and
        protocol-relative `//host` URLs (urlparse reads `//host` as netloc with
        an empty scheme — a classic open-redirect bypass). Rejected outside
        ENVIRONMENT=development/test: absolute URLs with a non-`https` scheme.
        """
        value = self.AUTH_OAUTH_POST_LOGIN_URL
        if not value:
            msg = "AUTH_OAUTH_POST_LOGIN_URL must not be empty"
            raise ValueError(msg)

        parsed = urlparse(value)

        # Protocol-relative (`//evil.com/path`): no scheme but a netloc. urlparse
        # treats this as having a host — reject before the relative-path branch.
        if not parsed.scheme and parsed.netloc:
            msg = (
                "AUTH_OAUTH_POST_LOGIN_URL must not be protocol-relative "
                f"(`//host`), got: {value!r}"
            )
            raise ValueError(msg)

        # Same-origin relative URL: starts with a single `/` (not `//`), no scheme,
        # no netloc. This is the safe common case.
        if not parsed.scheme and not parsed.netloc:
            if not value.startswith("/"):
                msg = (
                    "AUTH_OAUTH_POST_LOGIN_URL must be an absolute https URL or a "
                    f"same-origin path starting with '/', got: {value!r}"
                )
                raise ValueError(msg)
            return self

        # Absolute URL from here on. Reject dangerous schemes outright.
        if parsed.scheme not in {"http", "https"}:
            msg = (
                "AUTH_OAUTH_POST_LOGIN_URL scheme must be https (or http in "
                f"development/test), got: {parsed.scheme!r}"
            )
            raise ValueError(msg)

        # Non-https absolute URL only tolerated in development/test.
        if parsed.scheme != "https" and self.ENVIRONMENT not in {"development", "test"}:
            msg = (
                "AUTH_OAUTH_POST_LOGIN_URL must use https:// outside "
                f"ENVIRONMENT=development/test, got: {value!r}"
            )
            raise ValueError(msg)

        # Host must be in the allowlist derived from the other trusted URL settings.
        allowed_hosts = {_host_of(self.AUTH_OAUTH_REDIRECT_BASE_URL)}
        allowed_hosts.update(_host_of(origin) for origin in self.CORS_ORIGINS)
        allowed_hosts.discard(None)

        host = parsed.hostname.lower() if parsed.hostname else None
        if host not in allowed_hosts:
            msg = (
                f"AUTH_OAUTH_POST_LOGIN_URL host {host!r} is not in the allowlist "
                f"derived from AUTH_OAUTH_REDIRECT_BASE_URL + CORS_ORIGINS "
                f"({sorted(h for h in allowed_hosts if h)}), got: {value!r}"
            )
            raise ValueError(msg)

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
