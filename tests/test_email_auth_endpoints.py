"""Tests for the email/password auth endpoints — register, login, providers (#43).

The DB layer is mocked (AsyncMock session) and the service functions the router
calls (`create_email_user`, `authenticate_user`, `store_refresh_token`,
`get_subscription_status`, `_load_user_roles`) are patched per-test, so these
exercise the router contract — status codes, the token-response shape, validation,
and the security posture (generic 401, no enumeration) — without a real database.
"""

import uuid
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.services.user import EmailAlreadyRegisteredError


def _test_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "JWT_PRIVATE_KEY": "",
        "JWT_PUBLIC_KEY": "",
        # Limiter fails open (Redis uninitialized in tests); keep it off so the
        # warning log path is skipped entirely.
        "AUTH_RATE_LIMIT_ENABLED": False,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def settings() -> Settings:
    return _test_settings()


@pytest.fixture
async def client(settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db_session] = lambda: AsyncMock()
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _fake_user(email: str = "user@example.com", *, is_active: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        email=email,
        is_active=is_active,
        last_login_at=None,
    )


class TestRegister:
    async def test_register_happy_path_returns_tokens(self, client: AsyncClient) -> None:
        user = _fake_user("new@example.com")
        with (
            patch(
                "src.app.routers.auth.create_email_user",
                new=AsyncMock(return_value=user),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new=AsyncMock(return_value="free"),
            ),
            patch("src.app.routers.auth.store_refresh_token", new=AsyncMock()),
        ):
            resp = await client.post(
                "/auth/register",
                json={"email": "new@example.com", "password": "correct horse battery"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["token_type"] == "bearer"
        assert isinstance(data["expires_in"], int)

    async def test_register_duplicate_email_conflicts(self, client: AsyncClient) -> None:
        with patch(
            "src.app.routers.auth.create_email_user",
            new=AsyncMock(side_effect=EmailAlreadyRegisteredError("dup@example.com")),
        ):
            resp = await client.post(
                "/auth/register",
                json={"email": "dup@example.com", "password": "correct horse battery"},
            )
        assert resp.status_code == 409
        # Generic message — does not echo the address back.
        assert "dup@example.com" not in resp.json()["detail"]

    async def test_register_short_password_rejected(self, client: AsyncClient) -> None:
        # Default AUTH_PASSWORD_MIN_LENGTH is 8; "short1" is 6 chars.
        resp = await client.post(
            "/auth/register",
            json={"email": "x@example.com", "password": "short1"},
        )
        assert resp.status_code == 422

    async def test_register_invalid_email_rejected(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": "correct horse battery"},
        )
        assert resp.status_code == 422

    async def test_register_overlong_password_rejected(self, client: AsyncClient) -> None:
        # 73 bytes exceeds the bcrypt 72-byte ceiling — rejected, not truncated.
        resp = await client.post(
            "/auth/register",
            json={"email": "long@example.com", "password": "a" * 73},
        )
        assert resp.status_code == 422
        assert "72" in resp.json()["detail"]


class TestLogin:
    async def test_login_happy_path_returns_tokens(self, client: AsyncClient) -> None:
        user = _fake_user("known@example.com")
        with (
            patch(
                "src.app.routers.auth.authenticate_user",
                new=AsyncMock(return_value=user),
            ),
            patch(
                "src.app.routers.auth._load_user_roles",
                new=AsyncMock(return_value=["researcher"]),
            ),
            patch(
                "src.app.routers.auth.get_subscription_status",
                new=AsyncMock(return_value="active"),
            ),
            patch("src.app.routers.auth.store_refresh_token", new=AsyncMock()),
        ):
            resp = await client.post(
                "/auth/login",
                json={"email": "known@example.com", "password": "correct horse battery"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["token_type"] == "bearer"

    async def test_login_wrong_credentials_generic_401(self, client: AsyncClient) -> None:
        # authenticate_user collapses every failure to None → one generic 401.
        with patch(
            "src.app.routers.auth.authenticate_user",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.post(
                "/auth/login",
                json={"email": "known@example.com", "password": "wrong-password"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

    async def test_login_unknown_email_same_401(self, client: AsyncClient) -> None:
        # Unknown email and wrong password are indistinguishable to the caller.
        with patch(
            "src.app.routers.auth.authenticate_user",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.post(
                "/auth/login",
                json={"email": "nobody@example.com", "password": "correct horse battery"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"


class TestProviders:
    async def test_providers_lists_email_and_oauth(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/providers")
        assert resp.status_code == 200
        providers = {p["id"]: p for p in resp.json()["providers"]}
        # Email is always available.
        assert providers["email"]["type"] == "password"
        assert providers["email"]["enabled"] is True
        # All four OAuth providers are listed; unconfigured → disabled.
        for pid in ("google", "github", "apple", "facebook"):
            assert providers[pid]["type"] == "oauth"
            assert providers[pid]["enabled"] is False

    async def test_provider_enabled_when_configured(self) -> None:
        configured = _test_settings(
            AUTH_GOOGLE_CLIENT_ID="gid",
            AUTH_GOOGLE_CLIENT_SECRET="gsecret",
        )
        app = create_app()
        app.dependency_overrides[get_settings] = lambda: configured
        app.dependency_overrides[get_db_session] = lambda: AsyncMock()
        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/auth/providers")
        assert resp.status_code == 200
        providers = {p["id"]: p for p in resp.json()["providers"]}
        assert providers["google"]["enabled"] is True
        # An unconfigured sibling stays disabled.
        assert providers["github"]["enabled"] is False
