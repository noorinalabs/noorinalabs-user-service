from functools import lru_cache
from typing import Self
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings

_ALLOWED_OVERRIDE_SCHEMES = frozenset({"http", "https"})
_PROD_LIKE_ENVIRONMENTS = frozenset({"production", "staging"})
_ALLOWED_ENVIRONMENTS = frozenset({"development", "test", "staging", "production"})


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


@lru_cache
def get_settings() -> Settings:
    return Settings()
