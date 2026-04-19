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

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session, get_redis
from src.app.main import create_app
from src.app.models.user import User
from src.app.schemas.auth import OAuthUserInfo
from src.app.services.user import OAuthUserResult


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
        assert "token" in qs
        assert qs["is_new_user"] == ["0"]
        assert qs["needs_verification"] == ["0"]
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
                assert "token=" in first.headers["location"]

                # Same client instance — the FakeRedis is shared; state key was consumed.
                second = await client.get(
                    "/auth/oauth/google/callback",
                    params={"code": "abc", "state": state},
                )
                assert second.status_code == 302
                assert "error=invalid_state" in second.headers["location"]


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
