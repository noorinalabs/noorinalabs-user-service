"""Integration-style tests for auth endpoints using mocked DB sessions."""

import uuid
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.services.token import create_access_token


def _test_settings() -> Settings:
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_PRIVATE_KEY="",
        JWT_PUBLIC_KEY="",
    )


@pytest.fixture
def settings() -> Settings:
    return _test_settings()


@pytest.fixture
async def client(settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    # Override settings
    app.dependency_overrides[get_settings] = lambda: settings

    # Mock DB session
    mock_session = AsyncMock()
    app.dependency_overrides[get_db_session] = lambda: mock_session

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestJWKSEndpoint:
    async def test_jwks_returns_keys(self, client: AsyncClient) -> None:
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"


class TestValidateEndpoint:
    async def test_valid_token(self, client: AsyncClient, settings: Settings) -> None:
        user_id = uuid.uuid4()
        token, _ = create_access_token(
            settings, user_id, "test@example.com", ["researcher"], "active"
        )
        resp = await client.get(
            "/auth/token/validate",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["user_id"] == str(user_id)
        assert data["email"] == "test@example.com"
        assert data["roles"] == ["researcher"]
        assert data["subscription_status"] == "active"

    async def test_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/auth/token/validate",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False

    async def test_missing_bearer_prefix(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/auth/token/validate",
            headers={"Authorization": "Basic sometoken"},
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    async def test_missing_auth_header(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/token/validate")
        assert resp.status_code == 422  # FastAPI validation error


class TestRevokeEndpoint:
    async def test_revoke_nonexistent_token(self, client: AsyncClient) -> None:
        """Revoking a token that doesn't exist returns 400."""
        with patch(
            "src.app.routers.auth.revoke_refresh_token", new_callable=AsyncMock
        ) as mock_revoke:
            mock_revoke.return_value = False
            resp = await client.post(
                "/auth/token/revoke",
                json={"refresh_token": "nonexistent"},
            )
            assert resp.status_code == 400


class TestRefreshEndpoint:
    """POST /auth/token/refresh reads the refresh token from the httpOnly cookie
    (browser/OAuth clients) with a JSON-body fallback (non-browser callers), and
    rotates the cookie on success.

    Regression guard for the frontend↔backend contract drift: the cookie-based
    frontend POSTs an EMPTY body, which used to hit `body: RefreshRequest` and
    always 422. That silently broke every browser refresh — and, via the cold-
    login refresh safety net, wedged OAuth sign-in on a blank page.
    """

    async def test_empty_body_no_cookie_returns_401_not_422(self, client: AsyncClient) -> None:
        """The frontend's exact (broken) request — empty JSON body, no cookie —
        now returns a clean 401 'Missing refresh token', never a 422."""
        with (
            patch("src.app.routers.auth.enforce_ip_rate_limit", new_callable=AsyncMock),
            patch("src.app.routers.auth.check_rate_limit", new_callable=AsyncMock),
        ):
            resp = await client.post(
                "/auth/token/refresh", headers={"Content-Type": "application/json"}
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Missing refresh token"

    async def test_token_read_from_cookie(self, client: AsyncClient) -> None:
        """A refresh_token cookie (empty body) is the value validated."""
        with (
            patch("src.app.routers.auth.enforce_ip_rate_limit", new_callable=AsyncMock),
            patch("src.app.routers.auth.check_rate_limit", new_callable=AsyncMock),
            patch(
                "src.app.routers.auth.validate_refresh_token", new_callable=AsyncMock
            ) as mock_validate,
        ):
            mock_validate.return_value = None  # short-circuit to 401 before the DB path
            client.cookies.set("refresh_token", "cookie-tok")
            resp = await client.post("/auth/token/refresh")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired refresh token"
        mock_validate.assert_awaited_once()
        assert mock_validate.await_args.args[1] == "cookie-tok"

    async def test_token_body_fallback(self, client: AsyncClient) -> None:
        """With no cookie, the JSON body is the fallback source (non-browser)."""
        with (
            patch("src.app.routers.auth.enforce_ip_rate_limit", new_callable=AsyncMock),
            patch("src.app.routers.auth.check_rate_limit", new_callable=AsyncMock),
            patch(
                "src.app.routers.auth.validate_refresh_token", new_callable=AsyncMock
            ) as mock_validate,
        ):
            mock_validate.return_value = None
            resp = await client.post("/auth/token/refresh", json={"refresh_token": "body-tok"})
        assert resp.status_code == 401
        assert mock_validate.await_args.args[1] == "body-tok"

    async def test_cookie_precedence_over_body(self, client: AsyncClient) -> None:
        """When both are present the cookie wins (the browser's source of truth)."""
        with (
            patch("src.app.routers.auth.enforce_ip_rate_limit", new_callable=AsyncMock),
            patch("src.app.routers.auth.check_rate_limit", new_callable=AsyncMock),
            patch(
                "src.app.routers.auth.validate_refresh_token", new_callable=AsyncMock
            ) as mock_validate,
        ):
            mock_validate.return_value = None
            client.cookies.set("refresh_token", "cookie-tok")
            resp = await client.post(
                "/auth/token/refresh",
                json={"refresh_token": "body-tok"},
            )
        assert resp.status_code == 401
        assert mock_validate.await_args.args[1] == "cookie-tok"

    async def test_happy_path_rotates_httponly_cookie(self, settings: Settings) -> None:
        """On success a fresh refresh token is minted and set as a NEW httpOnly
        cookie (rotation), and the presented token is not echoed back."""
        app = create_app()
        app.dependency_overrides[get_settings] = lambda: settings
        mock_session = AsyncMock()
        app.dependency_overrides[get_db_session] = lambda: mock_session

        user_id = uuid.uuid4()
        fake_session = SimpleNamespace(user_id=user_id)
        fake_user = SimpleNamespace(id=user_id, email="u@example.com", is_active=True)
        user_result = MagicMock()
        user_result.scalar_one_or_none.return_value = fake_user
        roles_result = MagicMock()
        roles_result.fetchall.return_value = [("admin",)]
        # The handler calls db.execute twice: user lookup, then roles.
        mock_session.execute.side_effect = [user_result, roles_result]

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        with (
            patch("src.app.routers.auth.enforce_ip_rate_limit", new_callable=AsyncMock),
            patch("src.app.routers.auth.check_rate_limit", new_callable=AsyncMock),
            patch(
                "src.app.routers.auth.validate_refresh_token",
                new_callable=AsyncMock,
                return_value=fake_session,
            ),
            patch("src.app.routers.auth.revoke_refresh_token", new_callable=AsyncMock),
            patch("src.app.routers.auth.store_refresh_token", new_callable=AsyncMock),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new_callable=AsyncMock,
                return_value="free",
            ),
        ):
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                ac.cookies.set("refresh_token", "old-tok")
                resp = await ac.post("/auth/token/refresh")

        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        set_cookie = resp.headers.get("set-cookie", "")
        assert "refresh_token=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "samesite=lax" in set_cookie.lower()
        # Rotation: the old (now-revoked) token must not be the new cookie value.
        assert "old-tok" not in set_cookie
