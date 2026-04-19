from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
