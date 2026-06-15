from functools import lru_cache
from typing import Self
from urllib.parse import quote, urlparse

from pydantic import computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings
from sqlalchemy import URL

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

    # Database — preferred config path is the separate component vars below
    # (DATABASE_HOST/PORT/USER/PASSWORD/NAME). When any component is set, the
    # connection URL is built in-app via sqlalchemy.URL.create, which URL-encodes
    # the password — so passwords containing `/`, `+`, `=`, `@`, etc. are handled
    # safely (#65). DATABASE_URL is retained as a backward-compatible fallback and
    # as the local-dev default; it is used verbatim only when no component is set.
    DATABASE_URL: str = (
        "postgresql+asyncpg://user_service:user_service_dev@localhost:5433/user_service"
    )
    DATABASE_HOST: str | None = None
    DATABASE_PORT: int = 5432
    DATABASE_USER: str | None = None
    DATABASE_PASSWORD: str | None = None
    DATABASE_NAME: str | None = None
    # Driver scheme used when building the URL from components.
    DATABASE_DRIVER: str = "postgresql+asyncpg"

    # Redis — preferred config path is the separate component vars below
    # (REDIS_HOST/PORT/PASSWORD/DB). When REDIS_HOST is set, the connection URL is
    # built in-app with the password URL-encoded via urllib.parse.quote — so a
    # base64 password containing `/` no longer terminates the URL authority and
    # crashes urlparse at startup (#65). REDIS_URL is the backward-compatible
    # fallback / local-dev default, used verbatim only when REDIS_HOST is unset.
    REDIS_URL: str = "redis://localhost:6380/0"
    REDIS_HOST: str | None = None
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str | None = None
    REDIS_DB: int = 0
    # Set true to use rediss:// (TLS) when building the URL from components.
    REDIS_TLS: bool = False

    # JWT (RS256)
    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    JWT_ALGORITHM: str = "RS256"
    # Access token lifetime. The 30-day refresh window means the intent is
    # month-long sessions via silent refresh (refresh-on-401 on the frontend);
    # a too-tight access window surfaced the session-expired modal too often when
    # a refresh hiccupped, so this was lengthened 15→60 min (us#166). Stays
    # env-overridable (JWT_ACCESS_TOKEN_EXPIRE_MINUTES).
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
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

    # SSO session cookie — parent-domain carry for Caddy `forward_auth` (us#171 /
    # deploy#458). A short-lived RS256-signed token minted from a valid app bearer
    # (POST /auth/sso-cookie) and dropped as a parent-domain cookie so a top-level
    # browser navigation to a sibling subdomain (e.g. isnad.{base}/grafana) carries
    # a credential GET /auth/forward-auth can validate. The app access token lives
    # only in SPA localStorage and is never sent on a top-level nav, which is why a
    # cookie is needed here.
    AUTH_SSO_COOKIE_NAME: str = "nl_sso"
    # Parent domain so every *.noorinalabs.com subdomain receives the cookie. Owner
    # accepted the widened cross-subdomain surface (us#171, 2026-06-14) in exchange
    # for the short TTL + HttpOnly below. Override per-env (e.g. a staging base).
    AUTH_SSO_COOKIE_DOMAIN: str = "noorinalabs.com"
    # Short TTL (seconds) — bounds the window in which a role revoked after mint can
    # still pass forward-auth (forward-auth trusts the signed claim, not a live DB
    # read, so it stays cheap on every Grafana request). Keep small.
    AUTH_SSO_COOKIE_TTL_SECONDS: int = 300
    # Secure flag on the SSO cookie. Must be True in production (HTTPS); set to False
    # only for local HTTP dev.
    AUTH_SSO_COOKIE_SECURE: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_database_url(self) -> str:
        """The Postgres connection URL the app should actually connect with.

        When DATABASE_HOST is set, build the URL from the component vars via
        ``sqlalchemy.URL.create`` (which URL-encodes the password), so a password
        with URL-unsafe characters can never corrupt the URL. Otherwise fall back
        to DATABASE_URL verbatim (backward compat / local-dev default).
        """
        if self.DATABASE_HOST is None:
            return self.DATABASE_URL
        return URL.create(
            drivername=self.DATABASE_DRIVER,
            username=self.DATABASE_USER,
            password=self.DATABASE_PASSWORD,
            host=self.DATABASE_HOST,
            port=self.DATABASE_PORT,
            database=self.DATABASE_NAME,
        ).render_as_string(hide_password=False)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_redis_url(self) -> str:
        """The Redis connection URL the app should actually connect with.

        When REDIS_HOST is set, build ``redis(s)://[:<encoded-password>@]host:port/db``
        with the password percent-encoded via ``urllib.parse.quote`` (so `/`, `@`,
        `:`, `#`, etc. survive urlparse). Otherwise fall back to REDIS_URL verbatim
        (backward compat / local-dev default).
        """
        if self.REDIS_HOST is None:
            return self.REDIS_URL
        scheme = "rediss" if self.REDIS_TLS else "redis"
        auth = ""
        if self.REDIS_PASSWORD:
            # safe="" so every URL-reserved char in the password is encoded.
            auth = f":{quote(self.REDIS_PASSWORD, safe='')}@"
        return f"{scheme}://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

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
            # A leading `/` followed by `/` or `\` is not same-origin: browsers
            # normalize `\` -> `/` in http(s) URLs per the WHATWG URL spec, so
            # `/\host` becomes the protocol-relative `//host` at navigation time
            # — a classic open-redirect bypass that slips past urlparse (which
            # does not treat `\` as a netloc delimiter). Reject any backslash:
            # there is no legitimate use for one in this path, and a blanket
            # reject closes the whole variant family (`/\`, `/foo\@host`, ...).
            if value.startswith(("//", "/\\")) or "\\" in value:
                msg = (
                    "AUTH_OAUTH_POST_LOGIN_URL must not contain backslashes or be "
                    f"protocol-relative, got: {value!r}"
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
