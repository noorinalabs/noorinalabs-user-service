"""Tests for AUTH_OAUTH_POST_LOGIN_URL validation — open-redirect hardening (#69).

The OAuth callback redirects the browser, with a freshly minted access token
attached, to AUTH_OAUTH_POST_LOGIN_URL. It is operator-controlled today (env var,
no `?next=` override) so not an exploitable open redirect — this validator is
defence-in-depth: a misconfigured/compromised deploy config must fail fast at
boot rather than divert token-bearing traffic to an attacker host.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.app.config import Settings


def _make_settings(**overrides: object) -> Settings:
    """Build a Settings instance with sane defaults for the post-login-URL tests.

    Defaults ENVIRONMENT=production so the strict (https-only, allowlisted-host)
    branch is exercised unless a test opts into development/test.
    """
    defaults: dict[str, object] = {
        "ENVIRONMENT": "production",
        "AUTH_OAUTH_REDIRECT_BASE_URL": "https://user-service.noorinalabs.com",
        "CORS_ORIGINS": ["https://app.noorinalabs.com", "https://noorinalabs.com"],
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


class TestPostLoginUrlAccepted:
    def test_relative_url_accepted(self) -> None:
        s = _make_settings(AUTH_OAUTH_POST_LOGIN_URL="/auth/callback")
        assert s.AUTH_OAUTH_POST_LOGIN_URL == "/auth/callback"

    def test_default_value_is_valid(self) -> None:
        # The shipped default must pass its own validator.
        s = _make_settings()
        assert s.AUTH_OAUTH_POST_LOGIN_URL == "/auth/callback"

    def test_absolute_url_on_redirect_base_host_accepted(self) -> None:
        s = _make_settings(
            AUTH_OAUTH_POST_LOGIN_URL="https://user-service.noorinalabs.com/auth/callback"
        )
        assert s.AUTH_OAUTH_POST_LOGIN_URL.endswith("/auth/callback")

    def test_absolute_url_on_cors_origin_host_accepted(self) -> None:
        # Host present in CORS_ORIGINS but not AUTH_OAUTH_REDIRECT_BASE_URL.
        s = _make_settings(AUTH_OAUTH_POST_LOGIN_URL="https://app.noorinalabs.com/auth/callback")
        assert s.AUTH_OAUTH_POST_LOGIN_URL == "https://app.noorinalabs.com/auth/callback"

    def test_host_match_is_case_insensitive(self) -> None:
        s = _make_settings(AUTH_OAUTH_POST_LOGIN_URL="https://APP.NoorinALabs.com/auth/callback")
        assert s.AUTH_OAUTH_POST_LOGIN_URL.startswith("https://APP")

    def test_http_absolute_url_allowed_in_development(self) -> None:
        # localhost dev: CORS_ORIGINS carries the http host, ENVIRONMENT=development.
        s = _make_settings(
            ENVIRONMENT="development",
            AUTH_OAUTH_REDIRECT_BASE_URL="http://localhost:8000",
            CORS_ORIGINS=["http://localhost:3000"],
            AUTH_OAUTH_POST_LOGIN_URL="http://localhost:3000/auth/callback",
        )
        assert s.AUTH_OAUTH_POST_LOGIN_URL == "http://localhost:3000/auth/callback"


class TestPostLoginUrlRejected:
    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="")

    def test_protocol_relative_url_rejected(self) -> None:
        with pytest.raises(ValidationError, match="protocol-relative"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="//evil.com/auth/callback")

    def test_javascript_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError, match="scheme must be https"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="javascript:alert(document.cookie)")

    def test_data_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError, match="scheme must be https"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="data:text/html,<script>1</script>")

    def test_off_allowlist_host_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not in the allowlist"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="https://evil.com/auth/callback")

    def test_http_absolute_url_rejected_in_production(self) -> None:
        # Host would be allowlisted, but http:// is rejected outside dev/test.
        with pytest.raises(ValidationError, match="must use https"):
            _make_settings(
                CORS_ORIGINS=["http://app.noorinalabs.com"],
                AUTH_OAUTH_POST_LOGIN_URL="http://app.noorinalabs.com/auth/callback",
            )

    def test_relative_url_without_leading_slash_rejected(self) -> None:
        with pytest.raises(ValidationError, match="starting with '/'"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="auth/callback")

    def test_backslash_relative_url_rejected(self) -> None:
        # `/\evil.com` passes urlparse as a relative path (backslash is not a
        # netloc delimiter), but browsers normalize `\`->`/`, turning it into the
        # protocol-relative `//evil.com` at navigation time — CWE-601 bypass.
        with pytest.raises(ValidationError, match="must not contain backslashes"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="/\\evil.com")

    def test_backslash_anywhere_in_relative_url_rejected(self) -> None:
        # Blanket backslash reject — not just the leading `/\` case.
        with pytest.raises(ValidationError, match="must not contain backslashes"):
            _make_settings(AUTH_OAUTH_POST_LOGIN_URL="/auth\\callback")
