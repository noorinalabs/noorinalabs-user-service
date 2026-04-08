"""Tests for Subscription API endpoints and service logic."""

import hashlib
import hmac as hmac_mod
import json
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

from src.app.config import Settings
from src.app.database import get_db_session
from src.app.main import create_app
from src.app.models.role import Role, UserRole
from src.app.models.subscription import Subscription, SubscriptionPlan, SubscriptionStatus
from src.app.models.user import Base, User
from src.app.services import subscription as sub_svc

WEBHOOK_SECRET = "test-webhook-secret-123"

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


def _make_token(
    user_id: uuid.UUID,
    roles: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    exp = datetime.now(UTC) + (expires_delta or timedelta(hours=1))
    payload = {"sub": str(user_id), "exp": exp}
    if roles:
        payload["roles"] = roles  # type: ignore[assignment]
    return jwt.encode(payload, TEST_PRIVATE_PEM, algorithm="RS256")


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
    user = User(
        email="admin@test.com",
        display_name="Admin User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=seed_roles["admin"].id,
        granted_by=user.id,
    )
    db_session.add(user_role)
    await db_session.commit()
    return user


@pytest.fixture
async def regular_user(db_session: AsyncSession, seed_roles: dict[str, Role]) -> User:
    user = User(
        email="reader@test.com",
        display_name="Regular User",
        email_verified=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=seed_roles["reader"].id,
    )
    db_session.add(user_role)
    await db_session.commit()
    return user


@pytest.fixture
async def client(
    db_engine,  # type: ignore[no-untyped-def]
    db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()

    def _override_settings() -> Settings:
        return Settings(
            JWT_PUBLIC_KEY=TEST_PUBLIC_PEM,
            DATABASE_URL="sqlite+aiosqlite://",
            WEBHOOK_SIGNING_SECRET=WEBHOOK_SECRET,
        )

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    from src.app.config import get_settings

    app.dependency_overrides[get_settings] = _override_settings
    app.dependency_overrides[get_db_session] = _override_db

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _auth_header(user: User) -> dict[str, str]:
    token = _make_token(user.id)
    return {"Authorization": f"Bearer {token}"}


def _webhook_signature(body: bytes) -> str:
    sig = hmac_mod.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return f"sha256={sig}"


# --- Service-level tests ---


class TestSubscriptionService:
    @pytest.mark.asyncio
    async def test_get_subscription_status_no_sub(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        status = await sub_svc.get_subscription_status(db_session, regular_user.id)
        assert status == "free"

    @pytest.mark.asyncio
    async def test_start_trial(self, db_session: AsyncSession, regular_user: User) -> None:
        sub = await sub_svc.start_trial(db_session, regular_user.id)
        await db_session.commit()
        assert sub.plan == SubscriptionPlan.trial
        assert sub.status == SubscriptionStatus.active
        assert sub.expires_at is not None
        delta = sub.expires_at - sub.starts_at
        assert 13 < delta.days <= 14

    @pytest.mark.asyncio
    async def test_one_trial_per_user(self, db_session: AsyncSession, regular_user: User) -> None:
        await sub_svc.start_trial(db_session, regular_user.id)
        await db_session.commit()
        with pytest.raises(ValueError, match="already used their trial"):
            await sub_svc.start_trial(db_session, regular_user.id)

    @pytest.mark.asyncio
    async def test_create_subscription(self, db_session: AsyncSession, regular_user: User) -> None:
        sub = await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        assert sub.plan == SubscriptionPlan.researcher
        assert sub.status == SubscriptionStatus.active

    @pytest.mark.asyncio
    async def test_cancel_subscription(self, db_session: AsyncSession, regular_user: User) -> None:
        await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        cancelled = await sub_svc.cancel_subscription(db_session, regular_user.id)
        assert cancelled is not None
        assert cancelled.status == SubscriptionStatus.cancelled
        assert cancelled.expires_at is not None

    @pytest.mark.asyncio
    async def test_cancel_no_subscription(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        result = await sub_svc.cancel_subscription(db_session, regular_user.id)
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_subscription_detected(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        sub = Subscription(
            user_id=regular_user.id,
            plan=SubscriptionPlan.trial,
            status=SubscriptionStatus.active,
            starts_at=datetime.now(UTC) - timedelta(days=15),
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(sub)
        await db_session.commit()
        status = await sub_svc.get_subscription_status(db_session, regular_user.id)
        assert status == "expired"


# --- API endpoint tests ---


class TestGetMySubscription:
    @pytest.mark.asyncio
    async def test_no_subscription_returns_404(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        resp = await client.get("/api/v1/subscriptions/me", headers=_auth_header(regular_user))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_subscription(
        self, client: AsyncClient, regular_user: User, db_session: AsyncSession
    ) -> None:
        await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        resp = await client.get("/api/v1/subscriptions/me", headers=_auth_header(regular_user))
        assert resp.status_code == 200
        assert resp.json()["plan"] == "researcher"

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/subscriptions/me")
        assert resp.status_code in (401, 422)


class TestCreateSubscription:
    @pytest.mark.asyncio
    async def test_admin_can_create(
        self, client: AsyncClient, admin_user: User, regular_user: User
    ) -> None:
        resp = await client.post(
            "/api/v1/subscriptions",
            headers=_auth_header(admin_user),
            json={"user_id": str(regular_user.id), "plan": "researcher"},
        )
        assert resp.status_code == 201
        assert resp.json()["plan"] == "researcher"
        assert resp.json()["status"] == "active"

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.post(
            "/api/v1/subscriptions",
            headers=_auth_header(regular_user),
            json={"user_id": str(regular_user.id), "plan": "researcher"},
        )
        assert resp.status_code == 403


class TestStartTrial:
    @pytest.mark.asyncio
    async def test_start_trial_success(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.post(
            "/api/v1/subscriptions/trial",
            headers=_auth_header(regular_user),
            json={},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["plan"] == "trial"
        assert data["status"] == "active"
        assert data["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_duplicate_trial_rejected(self, client: AsyncClient, regular_user: User) -> None:
        await client.post(
            "/api/v1/subscriptions/trial",
            headers=_auth_header(regular_user),
            json={},
        )
        resp = await client.post(
            "/api/v1/subscriptions/trial",
            headers=_auth_header(regular_user),
            json={},
        )
        assert resp.status_code == 409


class TestCancelMySubscription:
    @pytest.mark.asyncio
    async def test_cancel_success(
        self, client: AsyncClient, regular_user: User, db_session: AsyncSession
    ) -> None:
        await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        resp = await client.delete(
            "/api/v1/subscriptions/me",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"
        assert resp.json()["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_cancel_no_active_subscription(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        resp = await client.delete(
            "/api/v1/subscriptions/me",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 404


class TestGetUserSubscription:
    @pytest.mark.asyncio
    async def test_admin_can_view(
        self, client: AsyncClient, admin_user: User, regular_user: User, db_session: AsyncSession
    ) -> None:
        await sub_svc.create_subscription(db_session, regular_user.id, "institutional")
        await db_session.commit()
        resp = await client.get(
            f"/api/v1/subscriptions/{regular_user.id}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 200
        assert resp.json()["plan"] == "institutional"

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self, client: AsyncClient, regular_user: User) -> None:
        resp = await client.get(
            f"/api/v1/subscriptions/{regular_user.id}",
            headers=_auth_header(regular_user),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_no_subscription_returns_404(
        self, client: AsyncClient, admin_user: User
    ) -> None:
        resp = await client.get(
            f"/api/v1/subscriptions/{uuid.uuid4()}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 404


class TestWebhook:
    @pytest.mark.asyncio
    async def test_subscription_created(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        payload = json.dumps({
            "event_type": "subscription.created",
            "user_id": str(regular_user.id),
            "plan": "researcher",
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "processed"

    @pytest.mark.asyncio
    async def test_unknown_event_ignored(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        payload = json.dumps({
            "event_type": "invoice.paid",
            "user_id": str(regular_user.id),
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        payload = json.dumps({
            "event_type": "subscription.created",
            "user_id": str(regular_user.id),
            "plan": "researcher",
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": "sha256=invalid",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            json={
                "event_type": "subscription.created",
                "user_id": str(regular_user.id),
                "plan": "researcher",
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_subscription_cancelled(
        self, client: AsyncClient, regular_user: User, db_session: AsyncSession
    ) -> None:
        await sub_svc.create_subscription(
            db_session, regular_user.id, "researcher"
        )
        await db_session.commit()
        payload = json.dumps({
            "event_type": "subscription.cancelled",
            "user_id": str(regular_user.id),
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "processed"

    @pytest.mark.asyncio
    async def test_subscription_updated(
        self, client: AsyncClient, regular_user: User, db_session: AsyncSession
    ) -> None:
        await sub_svc.create_subscription(
            db_session, regular_user.id, "researcher"
        )
        await db_session.commit()
        payload = json.dumps({
            "event_type": "subscription.updated",
            "user_id": str(regular_user.id),
            "status": "suspended",
            "plan": "institutional",
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "processed"

    @pytest.mark.asyncio
    async def test_webhook_invalid_status_rejected(
        self, client: AsyncClient, regular_user: User
    ) -> None:
        payload = json.dumps({
            "event_type": "subscription.updated",
            "user_id": str(regular_user.id),
            "status": "bogus_status",
        }).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 422
