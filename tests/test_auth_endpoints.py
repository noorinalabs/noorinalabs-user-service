"""Integration-style tests for auth endpoints using mocked DB sessions."""

import uuid
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

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
