"""Integration tests for the server-side GET OAuth callback handler.

Covers the flow added in #66 — the endpoint the OAuth provider redirects the
user's browser to after consent. The POST callback that this replaces never
had a test (nothing called it); this suite asserts the new contract.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session, get_redis
from src.app.main import create_app
from src.app.models.user import User
from src.app.schemas.auth import OAuthUserInfo
from src.app.services.user import (
    AccountExistsWithDifferentMethodError,
    OAuthUserResult,
)


def _test_settings() -> Settings:
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_PRIVATE_KEY="",
        JWT_PUBLIC_KEY="",
        AUTH_OAUTH_REDIRECT_BASE_URL="https://isnad-graph.noorinalabs.com",
        AUTH_OAUTH_POST_LOGIN_URL="/auth/callback",
        AUTH_OAUTH_STATE_TTL_SECONDS=600,
        AUTH_OAUTH_REFRESH_COOKIE_SECURE=True,
    )


class _FakeRedis:
    """Minimal in-memory stand-in for the async Redis client.

    Implements only the methods the auth router actually calls on the callback
    path (setex, getdel) so tests don't need a live Redis.
    """

    def __init__(self, seed: dict[str, str] | None = None) -> None:
        self._store: dict[str, bytes] = {
            k: v.encode() if isinstance(v, str) else v for k, v in (seed or {}).items()
        }

    async def setex(self, key: str, _ttl: int, value: str | bytes) -> None:
        self._store[key] = value.encode() if isinstance(value, str) else value

    async def getdel(self, key: str) -> bytes | None:
        return self._store.pop(key, None)


@pytest.fixture
def settings() -> Settings:
    return _test_settings()


@pytest.fixture
def fake_user() -> User:
    return User(
        id=uuid.uuid4(),
        email="mateo@example.com",
        email_verified=True,
        display_name="Mateo Test",
        avatar_url=None,
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture
async def client_factory(
    settings: Settings,
) -> AsyncGenerator[Any, None]:
    """Factory yielding a client bound to a given FakeRedis + mocked DB session.

    The callback handler doesn't actually execute SQL against the mock — the
    service-layer calls are patched at module scope — but get_db_session must
    still yield something so FastAPI's DI is satisfied.
    """

    async def _make(redis_seed: dict[str, str] | None = None) -> AsyncClient:
        app = create_app()
        app.dependency_overrides[get_settings] = lambda: settings
        mock_db = AsyncMock()
        # db.execute(...) must return something with .fetchall() for the roles query
        roles_result = MagicMock()
        roles_result.fetchall.return_value = []
        mock_db.execute = AsyncMock(return_value=roles_result)

        # Single FakeRedis shared across all requests made by this client. This is
        # what matters for the replay test — prod uses one redis client per app.
        shared_redis = _FakeRedis(redis_seed)

        async def _db_dep() -> AsyncGenerator[Any, None]:
            yield mock_db

        async def _redis_dep() -> AsyncGenerator[Any, None]:
            yield shared_redis

        app.dependency_overrides[get_db_session] = _db_dep
        app.dependency_overrides[get_redis] = _redis_dep

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        return AsyncClient(transport=transport, base_url="http://test", follow_redirects=False)

    yield _make


class TestOAuthCallbackGet:
    @pytest.mark.asyncio
    async def test_success_redirects_with_token_and_sets_cookie(
        self,
        client_factory: Any,
        fake_user: User,
    ) -> None:
        """Happy path — state valid, code exchange works, user upserted, redirect 302."""
        state = "valid-state-token"
        seed = {
            f"oauth_state:{state}": json.dumps(
                {"provider": "google", "code_verifier": "pkce-verifier"}
            ),
        }

        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g-123",
                email="mateo@example.com",
                display_name="Mateo Test",
                avatar_url=None,
            )
        )

        with (
            patch(
                "src.app.routers.auth.get_oauth_provider",
                return_value=oauth_mock,
            ),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                return_value=OAuthUserResult(user=fake_user, is_new_user=False),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new_callable=AsyncMock,
                return_value="free",
            ),
            patch(
                "src.app.routers.auth.store_refresh_token",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc123", "state": state},
                )

        assert resp.status_code == 302
        location = resp.headers["location"]
        parsed = urlparse(location)
        # Path must include the provider segment to match the frontend React
        # Router route `auth/callback/:provider`. Regression guard for the Anya
        # must-fix on PR#67.
        assert parsed.path == "/auth/callback/google"
        qs = parse_qs(parsed.query)
        # Per #68 the access token is delivered in the URL *fragment*, not the
        # query string — fragments are never sent in the Referer header. The
        # non-secret flags stay as query params.
        assert "token" not in qs
        assert qs["is_new_user"] == ["0"]
        assert qs["needs_verification"] == ["0"]
        frag = parse_qs(parsed.fragment)
        assert "token" in frag
        assert frag["token"][0]
        # Refresh token must be set as an httpOnly cookie
        set_cookie = resp.headers.get("set-cookie", "")
        assert "refresh_token=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "Secure" in set_cookie
        assert "SameSite=lax" in set_cookie.lower() or "samesite=lax" in set_cookie.lower()

    @pytest.mark.asyncio
    async def test_missing_state_redirects_with_invalid_state_error(
        self, client_factory: Any
    ) -> None:
        async with await client_factory({}) as client:
            resp = await client.get(
                "/auth/oauth/google/callback",
                params={"code": "abc123", "state": "nope"},
            )
        assert resp.status_code == 302
        # Error redirects must also carry the provider segment so the frontend
        # route matches and the `error=` param is read.
        parsed = urlparse(resp.headers["location"])
        assert parsed.path == "/auth/callback/google"
        assert "error=invalid_state" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_state_mismatched_provider_rejected(self, client_factory: Any) -> None:
        """State was created for google, attacker tries the github callback route."""
        state = "cross-provider-state"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        async with await client_factory(seed) as client:
            resp = await client.get(
                "/auth/oauth/github/callback",
                params={"code": "abc", "state": state},
            )
        assert resp.status_code == 302
        assert "error=invalid_state" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_provider_error_param_redirects_with_provider_denied(
        self, client_factory: Any
    ) -> None:
        """User declined consent — provider redirects with ?error=access_denied."""
        async with await client_factory({}) as client:
            resp = await client.get(
                "/auth/oauth/google/callback",
                params={"error": "access_denied"},
            )
        assert resp.status_code == 302
        assert "error=provider_denied" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_unsupported_provider_redirects(self, client_factory: Any) -> None:
        async with await client_factory({}) as client:
            resp = await client.get(
                "/auth/oauth/myspace/callback",
                params={"code": "abc", "state": "anything"},
            )
        assert resp.status_code == 302
        assert "error=unsupported_provider" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_exchange_failure_redirects_with_error(self, client_factory: Any) -> None:
        state = "valid-state"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(side_effect=RuntimeError("provider down"))

        with patch(
            "src.app.routers.auth.get_oauth_provider",
            return_value=oauth_mock,
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )
        assert resp.status_code == 302
        assert "error=oauth_exchange_failed" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_user_info_failure_redirects_with_error(self, client_factory: Any) -> None:
        """Provider returns tokens but user-info fetch fails — distinct from exchange_failure.

        Filed under the review-requested gap on #70. Mirrors the exchange test but
        keeps exchange_code succeeding so we exercise the second try/except branch.
        """
        state = "valid-state-ui"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(side_effect=RuntimeError("userinfo 500"))

        with patch(
            "src.app.routers.auth.get_oauth_provider",
            return_value=oauth_mock,
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )
        assert resp.status_code == 302
        # Currently aliased to the same error code as exchange failures — the
        # frontend only distinguishes "provider misbehaved" from the other cases.
        # If that ever splits, this test will catch the unintentional collapse.
        parsed = urlparse(resp.headers["location"])
        assert parsed.path == "/auth/callback/google"
        assert "error=oauth_exchange_failed" in resp.headers["location"]
        # exchange_code must have been called (so we're truly testing the second branch)
        oauth_mock.exchange_code.assert_awaited_once()
        oauth_mock.get_user_info.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cross_method_collision_redirects_with_account_exists_and_method(
        self,
        client_factory: Any,
    ) -> None:
        """#153 / #154 — when the service rejects a cross-method link, the
        callback bounces the user back with `error=account_exists_different_method`
        and a `method` param the frontend renders as
        "{email} is already registered as {method}". No token is issued."""
        state = "collision-state"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "github", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="github",
                provider_account_id="gh-x",
                email="alice@example.com",
                display_name="Alice",
                avatar_url=None,
            )
        )

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                side_effect=AccountExistsWithDifferentMethodError(
                    email="alice@example.com", existing_methods=["google"]
                ),
            ),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/github/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        parsed = urlparse(resp.headers["location"])
        assert parsed.path == "/auth/callback/github"
        qs = parse_qs(parsed.query)
        assert qs["error"] == ["account_exists_different_method"]
        assert qs["method"] == ["google"]
        # No token must be minted on the rejection path.
        assert "token" not in qs
        assert "token" not in parse_qs(parsed.fragment)
        # No refresh cookie set either.
        assert "refresh_token=" not in resp.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_exchange_code_called_with_configured_redirect_uri(
        self,
        client_factory: Any,
        fake_user: User,
    ) -> None:
        """exchange_code must receive the redirect_uri built from AUTH_OAUTH_REDIRECT_BASE_URL.

        Gap 3 on #70. The happy-path test asserts the redirect *response* but
        never inspects what redirect_uri was handed to the provider. A prod
        misconfig (AUTH_OAUTH_REDIRECT_BASE_URL unset/wrong) would pass every
        other test and only fail at integration time with redirect_uri_mismatch.
        """
        state = "redirect-uri-state"
        seed = {
            f"oauth_state:{state}": json.dumps(
                {"provider": "google", "code_verifier": "pkce-verifier"}
            ),
        }

        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g-123",
                email="mateo@example.com",
                display_name="Mateo Test",
                avatar_url=None,
            )
        )

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                return_value=OAuthUserResult(user=fake_user, is_new_user=False),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new_callable=AsyncMock,
                return_value="free",
            ),
            patch(
                "src.app.routers.auth.store_refresh_token",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc123", "state": state},
                )

        assert resp.status_code == 302
        # _test_settings sets AUTH_OAUTH_REDIRECT_BASE_URL to this host; the
        # handler appends /auth/oauth/{provider}/callback.
        oauth_mock.exchange_code.assert_awaited_once_with(
            "abc123",
            "pkce-verifier",
            "https://isnad-graph.noorinalabs.com/auth/oauth/google/callback",
        )

    @pytest.mark.asyncio
    async def test_state_is_consumed_exactly_once(self, client_factory: Any) -> None:
        """Replaying the callback URL with the same state must fail the second time."""
        state = "replay-state"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        # Both calls would succeed at the provider level — the guard is at the state check.
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "t"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g",
                email="e@e.com",
                display_name=None,
                avatar_url=None,
            )
        )
        fake = User(
            id=uuid.uuid4(),
            email="e@e.com",
            email_verified=True,
            display_name=None,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                return_value=OAuthUserResult(user=fake, is_new_user=True),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new_callable=AsyncMock,
                return_value="free",
            ),
            patch(
                "src.app.routers.auth.store_refresh_token",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            async with await client_factory(seed) as client:
                first = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )
                assert first.status_code == 302
                # Token is in the fragment, not the query string (#68).
                first_parsed = urlparse(first.headers["location"])
                assert "token" in parse_qs(first_parsed.fragment)
                assert "token" not in parse_qs(first_parsed.query)

                # Same client instance — the FakeRedis is shared; state key was consumed.
                second = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )
                assert second.status_code == 302
                assert "error=invalid_state" in second.headers["location"]


class TestOAuthToTokenFlow:
    """End-to-end: OAuth callback issues a token, then /auth/token/validate
    accepts it (US#56 missing coverage).

    The individual legs are tested elsewhere — callback→redirect above,
    validate→200 in test_auth_endpoints.py — but nothing chains them. This
    pins that the access token the callback mints is one the validate
    endpoint actually accepts (same signing keypair, well-formed claims).
    """

    @pytest.mark.asyncio
    async def test_callback_issued_token_passes_validate(
        self,
        client_factory: Any,
        fake_user: User,
    ) -> None:
        state = "e2e-state-token"
        seed = {
            f"oauth_state:{state}": json.dumps(
                {"provider": "google", "code_verifier": "pkce-verifier"}
            ),
        }

        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g-123",
                email="mateo@example.com",
                display_name="Mateo Test",
                avatar_url=None,
            )
        )

        with (
            patch(
                "src.app.routers.auth.get_oauth_provider",
                return_value=oauth_mock,
            ),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                return_value=OAuthUserResult(user=fake_user, is_new_user=False),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new_callable=AsyncMock,
                return_value="free",
            ),
            patch(
                "src.app.routers.auth.store_refresh_token",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            async with await client_factory(seed) as client:
                callback_resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc123", "state": state},
                )
                assert callback_resp.status_code == 302
                # Token is delivered in the URL fragment (#68).
                fragment = parse_qs(urlparse(callback_resp.headers["location"]).fragment)
                token = fragment["token"][0]
                assert token

                # Feed the freshly-issued token straight back to validate.
                validate_resp = await client.get(
                    "/auth/token/validate",
                    headers={"Authorization": f"Bearer {token}"},
                )

        assert validate_resp.status_code == 200
        data = validate_resp.json()
        assert data["valid"] is True
        assert data["user_id"] == str(fake_user.id)
        assert data["email"] == fake_user.email


class TestPostCallbackRemoved:
    """The POST callback was dead code (no frontend caller); #66 removed it."""

    @pytest.mark.asyncio
    async def test_post_callback_returns_405(self, client_factory: Any) -> None:
        async with await client_factory({}) as client:
            resp = await client.post(
                "/auth/oauth/google/callback",
                json={"code": "a", "state": "b", "code_verifier": "c"},
            )
        # FastAPI replies 405 when only GET is registered on the path.
        assert resp.status_code == 405


class TestExchangeLoggingDiagnostics:
    """Issue #71 — silent OAuth exception handlers must emit structured logs.

    Prior to this issue, any failure in exchange_code/get_user_info/upsert was
    swallowed and the user was bounced with `?error=oauth_exchange_failed` and
    no log line. These tests pin the new contract: each exception path emits
    one log record on the `src.app.routers.auth` logger naming the provider
    (and HTTP status/body excerpt for httpx errors).
    """

    @pytest.mark.asyncio
    async def test_exchange_unexpected_exception_logs_provider(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state = "log-state-1"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(side_effect=RuntimeError("boom"))

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            caplog.at_level("ERROR", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1, f"expected 1 log record, got {len(records)}"
        msg = records[0].getMessage()
        assert "OAuth exchange unexpected error" in msg
        assert "google" in msg
        assert "RuntimeError" in msg
        # exception info captured (logger.exception sets exc_info)
        assert records[0].exc_info is not None

    @pytest.mark.asyncio
    async def test_exchange_httpx_status_error_logs_status_and_body(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state = "log-state-2"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        # Build a real httpx.HTTPStatusError so the handler's response.text/.status_code work.
        request = httpx.Request("POST", "https://oauth2.googleapis.com/token")
        response = httpx.Response(
            400,
            request=request,
            content=b'{"error":"invalid_grant","error_description":"Bad Request"}',
        )
        http_err = httpx.HTTPStatusError("400", request=request, response=response)

        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(side_effect=http_err)

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            caplog.at_level("ERROR", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        assert "error=oauth_exchange_failed" in resp.headers["location"]
        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1
        msg = records[0].getMessage()
        assert "OAuth exchange HTTP error" in msg
        assert "google" in msg
        assert "400" in msg
        assert "invalid_grant" in msg

    @pytest.mark.asyncio
    async def test_user_info_exception_logs_provider(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state = "log-state-3"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "github", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "ghtoken"})
        oauth_mock.get_user_info = AsyncMock(side_effect=RuntimeError("userinfo down"))

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            caplog.at_level("ERROR", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/github/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1
        msg = records[0].getMessage()
        assert "OAuth user_info unexpected error" in msg
        assert "github" in msg
        assert "RuntimeError" in msg

    @pytest.mark.asyncio
    async def test_upsert_value_error_logs_warning(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state = "log-state-4"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g-99",
                email="e@e.com",
                display_name=None,
                avatar_url=None,
            )
        )

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                side_effect=ValueError("email already linked to a different oauth account"),
            ),
            caplog.at_level("WARNING", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        assert "error=email_mismatch" in resp.headers["location"]
        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1
        assert records[0].levelname == "WARNING"
        msg = records[0].getMessage()
        assert "OAuth user upsert rejected" in msg
        assert "google" in msg
        assert "email already linked" in msg


class TestUpsertDbErrorHandling:
    """Issue #73 — DB-layer failures in find_or_create_oauth_user must bounce the
    user to the frontend with `?error=oauth_upsert_failed`, not escape as a 500.

    Prior to this issue the upsert path caught only ValueError; any
    SQLAlchemyError subclass (OperationalError, ProgrammingError,
    IntegrityError, DBAPIError, …) bubbled up as a raw 500. These tests pin the
    new contract:
      - the handler returns 302 with the generic upsert-failed code,
      - it logs at ERROR with exc_info (logger.exception),
      - the redirect carries ONLY the generic code — no DB detail leaks, and
      - the catch is the broad SQLAlchemyError base class, so it covers every
        DBAPI subclass (asserted directly against the route source, since a mock
        side_effect alone can't prove the handler didn't catch a narrower type —
        org memory: test-mock injection can mask production exception scope).
    """

    @pytest.mark.asyncio
    async def test_upsert_operational_error_redirects_and_logs(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from sqlalchemy.exc import OperationalError

        state = "db-state-1"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "google", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "gtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="google",
                provider_account_id="g-1",
                email="e@e.com",
                display_name=None,
                avatar_url=None,
            )
        )
        # statement/params carry sensitive SQL + connection detail — assert below
        # that none of it reaches the redirect URL.
        db_exc = OperationalError(
            'SELECT * FROM oauth_accounts WHERE token = "supersecret"',
            {"token": "supersecret"},
            Exception("could not connect to server: host=db.internal"),
        )

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                side_effect=db_exc,
            ),
            caplog.at_level("ERROR", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "error=oauth_upsert_failed" in location
        # No DB internals leak into the user-facing redirect.
        assert "supersecret" not in location
        assert "oauth_accounts" not in location
        assert "db.internal" not in location

        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1
        assert records[0].levelname == "ERROR"
        msg = records[0].getMessage()
        assert "OAuth upsert DB error" in msg
        assert "google" in msg
        assert "OperationalError" in msg
        # logger.exception attaches exc_info
        assert records[0].exc_info is not None

    @pytest.mark.asyncio
    async def test_upsert_programming_error_redirects_and_logs(
        self,
        client_factory: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # This is the exact prod failure that surfaced #73:
        # ProgrammingError: relation "oauth_accounts" does not exist.
        from sqlalchemy.exc import ProgrammingError

        state = "db-state-2"
        seed = {
            f"oauth_state:{state}": json.dumps({"provider": "github", "code_verifier": "verifier"}),
        }
        oauth_mock = MagicMock()
        oauth_mock.exchange_code = AsyncMock(return_value={"access_token": "ghtoken"})
        oauth_mock.get_user_info = AsyncMock(
            return_value=OAuthUserInfo(
                provider="github",
                provider_account_id="gh-1",
                email="e@e.com",
                display_name=None,
                avatar_url=None,
            )
        )
        db_exc = ProgrammingError(
            "INSERT INTO oauth_accounts ...",
            {},
            Exception('relation "oauth_accounts" does not exist'),
        )

        with (
            patch("src.app.routers.auth.get_oauth_provider", return_value=oauth_mock),
            patch(
                "src.app.routers.auth.find_or_create_oauth_user",
                new_callable=AsyncMock,
                side_effect=db_exc,
            ),
            caplog.at_level("ERROR", logger="src.app.routers.auth"),
        ):
            async with await client_factory(seed) as client:
                resp = await client.get(
                    "/auth/oauth/github/callback",
                    params={"code": "abc", "state": state},
                )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "error=oauth_upsert_failed" in location
        assert "oauth_accounts" not in location

        records = [r for r in caplog.records if r.name == "src.app.routers.auth"]
        assert len(records) == 1
        assert records[0].levelname == "ERROR"
        msg = records[0].getMessage()
        assert "OAuth upsert DB error" in msg
        assert "github" in msg
        assert "ProgrammingError" in msg
        assert records[0].exc_info is not None

    def test_handler_catches_sqlalchemy_base_class_not_narrower_subclass(self) -> None:
        """Static guard against exception-scope regression.

        A mock side_effect proves the handler catches *the type the mock raises*,
        but not that it catches the broad base class — if someone narrowed the
        catch to e.g. `OperationalError`, the OperationalError test above would
        still pass while a ProgrammingError at a different call site would once
        again escape as a 500 (org memory: test-mock injection masks production
        exception scope). So we assert against the route source directly: the
        upsert handler must catch `SQLAlchemyError` (the DBAPI base), and the
        module must import it from sqlalchemy.exc.
        """
        import inspect

        from sqlalchemy.exc import (
            DBAPIError,
            IntegrityError,
            OperationalError,
            ProgrammingError,
            SQLAlchemyError,
        )

        from src.app.routers import auth as auth_module

        # The imported symbol the handler relies on must be the broad base class,
        # and every DBAPI subclass the issue enumerates must be a subclass of it.
        assert auth_module.SQLAlchemyError is SQLAlchemyError
        for subclass in (DBAPIError, OperationalError, ProgrammingError, IntegrityError):
            assert issubclass(subclass, SQLAlchemyError)

        src = inspect.getsource(auth_module.oauth_callback_get)
        assert "except SQLAlchemyError" in src, (
            "oauth_callback_get must catch the SQLAlchemyError base class, not a "
            "narrower DBAPI subclass — a narrower catch lets sibling DB errors "
            "escape as a 500 (#73)."
        )
