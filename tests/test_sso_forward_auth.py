"""Tests for the parent-domain SSO session cookie + GET /auth/forward-auth.

Covers the user-service third of the deploy#458 admin-gated-Grafana feature
(us#171):

  * POST /auth/sso-cookie — authenticated mint of a short-lived, RS256-signed
    parent-domain cookie (attributes + TTL + signature + claims).
  * GET /auth/forward-auth — cookie-based gate Caddy's forward_auth calls:
    200 + X-Webauth-* for an admin with a valid cookie, 401 for no/invalid/expired
    cookie, 403 for a valid cookie whose user is not an admin.
"""

import re
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.app.config import Settings, get_settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.models.role import Role, UserRole
from src.app.models.user import Base, User
from src.app.services.token import create_sso_token

# --- Test RSA keypair (the service's signing/verification key for these tests) ---
_test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PRIVATE_PEM = _test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
TEST_PUBLIC_PEM = (
    _test_private_key.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode()
)

# A *different* keypair — used to forge a cookie the service must reject.
_other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PRIVATE_PEM = _other_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

COOKIE_NAME = "nl_sso"


def _test_settings() -> Settings:
    return Settings(
        JWT_PRIVATE_KEY=TEST_PRIVATE_PEM,
        JWT_PUBLIC_KEY=TEST_PUBLIC_PEM,
        DATABASE_URL="sqlite+aiosqlite://",
    )


def _access_token(user_id: uuid.UUID, roles: list[str] | None = None) -> str:
    """Mint an app access token (the Bearer the mint endpoint authenticates)."""
    payload: dict[str, object] = {
        "sub": str(user_id),
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "type": "access",
    }
    if roles:
        payload["roles"] = roles
    return jwt.encode(payload, TEST_PRIVATE_PEM, algorithm="RS256")


def _sso_cookie_token(
    *,
    user_id: uuid.UUID | None = None,
    email: str = "admin@test.com",
    roles: list[str] | None = None,
    ttl_seconds: int = 300,
    private_pem: str = TEST_PRIVATE_PEM,
    token_type: str = "sso",
) -> str:
    """Build an SSO cookie token directly for forward-auth unit coverage."""
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "sub": str(user_id or uuid.uuid4()),
        "email": email,
        "roles": roles if roles is not None else ["admin"],
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "type": token_type,
    }
    return jwt.encode(payload, private_pem, algorithm="RS256")


@pytest.fixture
async def db_engine():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:  # type: ignore[no-untyped-def, type-arg]
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def seed_roles(db_session: AsyncSession) -> dict[str, Role]:
    roles = {}
    for name, desc in [
        ("admin", "Full platform administration access"),
        ("researcher", "Access to research tools and datasets"),
        ("reader", "Read-only access to public content"),
        ("trial", "Time-limited trial access"),
    ]:
        role = Role(name=name, description=desc)
        db_session.add(role)
        roles[name] = role
    await db_session.commit()
    return roles


@pytest.fixture
async def admin_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(email="admin@test.com", display_name="Admin", email_verified=True, is_active=True)
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["admin"].id, granted_by=user.id))
    await db_session.commit()
    return user


@pytest.fixture
async def regular_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(email="reader@test.com", display_name="Reader", email_verified=True, is_active=True)
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(user_id=user.id, role_id=seed_roles["reader"].id))
    await db_session.commit()
    return user


@pytest.fixture
async def client(
    db_engine,  # type: ignore[no-untyped-def]
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_settings] = _test_settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _cookie_value(set_cookie_header: str) -> str:
    match = re.search(rf"{COOKIE_NAME}=([^;]+)", set_cookie_header)
    assert match is not None, f"no {COOKIE_NAME} cookie in: {set_cookie_header!r}"
    return match.group(1)


# --- Mint endpoint -----------------------------------------------------------


class TestMintSsoCookie:
    @pytest.mark.asyncio
    async def test_admin_gets_cookie_with_security_attributes(
        self, client: AsyncClient, admin_user: User
    ) -> None:
        resp = await client.post(
            "/auth/sso-cookie",
            headers={"Authorization": f"Bearer {_access_token(admin_user.id)}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"status": "ok", "cookie_name": COOKIE_NAME, "expires_in": 300}

        set_cookie = resp.headers["set-cookie"].lower()
        assert f"{COOKIE_NAME}=" in set_cookie
        assert "domain=noorinalabs.com" in set_cookie
        assert "httponly" in set_cookie
        assert "secure" in set_cookie
        assert "samesite=lax" in set_cookie
        assert "max-age=300" in set_cookie
        assert "path=/" in set_cookie

    @pytest.mark.asyncio
    async def test_minted_token_is_signed_and_carries_claims(
        self, client: AsyncClient, admin_user: User
    ) -> None:
        resp = await client.post(
            "/auth/sso-cookie",
            headers={"Authorization": f"Bearer {_access_token(admin_user.id)}"},
        )
        token = _cookie_value(resp.headers["set-cookie"])
        # Verifiable with the service public key — i.e. genuinely RS256-signed.
        payload = jwt.decode(token, TEST_PUBLIC_PEM, algorithms=["RS256"])
        assert payload["type"] == "sso"
        assert payload["sub"] == str(admin_user.id)
        assert payload["email"] == admin_user.email
        assert payload["roles"] == ["admin"]
        # TTL ~ 300s in the future.
        ttl = payload["exp"] - payload["iat"]
        assert ttl == 300

    @pytest.mark.asyncio
    async def test_non_admin_also_receives_a_cookie(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        # Any authenticated user may mint — admin gating is enforced at
        # forward-auth (403), not at the mint endpoint.
        resp = await client.post(
            "/auth/sso-cookie",
            headers={"Authorization": f"Bearer {_access_token(regular_user.id)}"},
        )
        assert resp.status_code == 200
        token = _cookie_value(resp.headers["set-cookie"])
        payload = jwt.decode(token, TEST_PUBLIC_PEM, algorithms=["RS256"])
        assert payload["roles"] == ["reader"]

    @pytest.mark.asyncio
    async def test_unauthenticated_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/sso-cookie")
        assert resp.status_code in (401, 422)

    @pytest.mark.asyncio
    async def test_invalid_bearer_rejected(self, client: AsyncClient) -> None:
        resp = await client.post("/auth/sso-cookie", headers={"Authorization": "Bearer not-a-jwt"})
        assert resp.status_code == 401


# --- Forward-auth gate -------------------------------------------------------


class TestForwardAuth:
    @pytest.mark.asyncio
    async def test_admin_valid_cookie_200_with_headers(self, client: AsyncClient) -> None:
        uid = uuid.uuid4()
        token = _sso_cookie_token(user_id=uid, email="admin@test.com", roles=["admin"])
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 200
        assert resp.headers["x-webauth-user"] == "admin@test.com"
        assert resp.headers["x-webauth-role"] == "admin"

    @pytest.mark.asyncio
    async def test_user_header_falls_back_to_sub_when_no_email(self, client: AsyncClient) -> None:
        uid = uuid.uuid4()
        token = _sso_cookie_token(user_id=uid, email="", roles=["admin"])
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 200
        assert resp.headers["x-webauth-user"] == str(uid)

    @pytest.mark.asyncio
    async def test_no_cookie_401(self, client: AsyncClient) -> None:
        resp = await client.get("/auth/forward-auth")
        assert resp.status_code == 401
        assert "x-webauth-user" not in resp.headers

    @pytest.mark.asyncio
    async def test_garbage_cookie_401(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}=not-a-jwt"}
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_foreign_signature_401(self, client: AsyncClient) -> None:
        # Correctly-shaped SSO token, but signed by a key the service doesn't trust.
        token = _sso_cookie_token(roles=["admin"], private_pem=OTHER_PRIVATE_PEM)
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_type_401(self, client: AsyncClient) -> None:
        # An access token (type=access) replayed as the SSO cookie must be rejected.
        token = _sso_cookie_token(roles=["admin"], token_type="access")
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_cookie_401(self, client: AsyncClient) -> None:
        token = _sso_cookie_token(roles=["admin"], ttl_seconds=-10)
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_non_admin_403(self, client: AsyncClient) -> None:
        token = _sso_cookie_token(roles=["reader"])
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 403
        assert "x-webauth-user" not in resp.headers

    @pytest.mark.asyncio
    async def test_no_roles_403(self, client: AsyncClient) -> None:
        token = _sso_cookie_token(roles=[])
        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 403


# --- End-to-end --------------------------------------------------------------


class TestMintThenForwardAuth:
    @pytest.mark.asyncio
    async def test_admin_roundtrip(self, client: AsyncClient, admin_user: User) -> None:
        mint = await client.post(
            "/auth/sso-cookie",
            headers={"Authorization": f"Bearer {_access_token(admin_user.id)}"},
        )
        token = _cookie_value(mint.headers["set-cookie"])

        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 200
        assert resp.headers["x-webauth-user"] == admin_user.email
        assert resp.headers["x-webauth-role"] == "admin"

    @pytest.mark.asyncio
    async def test_non_admin_roundtrip_403(self, client: AsyncClient, regular_user: User) -> None:
        mint = await client.post(
            "/auth/sso-cookie",
            headers={"Authorization": f"Bearer {_access_token(regular_user.id)}"},
        )
        token = _cookie_value(mint.headers["set-cookie"])

        resp = await client.get("/auth/forward-auth", headers={"Cookie": f"{COOKIE_NAME}={token}"})
        assert resp.status_code == 403


def test_sso_token_service_roundtrip() -> None:
    """create_sso_token → decode_sso_token returns the same claims."""
    from src.app.services.token import decode_sso_token

    settings = _test_settings()
    uid = uuid.uuid4()
    token, expires_at = create_sso_token(
        settings=settings,
        user_id=uid,
        email="x@test.com",
        roles=["admin"],
        ttl_seconds=300,
    )
    payload = decode_sso_token(settings, token)
    assert payload["sub"] == str(uid)
    assert payload["email"] == "x@test.com"
    assert payload["roles"] == ["admin"]
    assert payload["type"] == "sso"
    assert isinstance(expires_at, datetime)
