"""Tests for Subscription API endpoints and service logic.

Shared fixtures (RSA keygen, token helpers, db_engine/db_session/seed_roles/
admin_user/regular_user/client) live in tests/conftest.py — see US#56. This
module overrides the `settings` fixture so the `client` picks up the webhook
signing secret the subscription webhook endpoint needs.
"""

import hashlib
import hmac as hmac_mod
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.config import Settings
from src.app.models.subscription import Subscription, SubscriptionPlan, SubscriptionStatus
from src.app.models.user import User
from src.app.services import subscription as sub_svc
from tests.conftest import auth_header as _auth_header
from tests.conftest import build_test_settings

WEBHOOK_SECRET = "test-webhook-secret-123"


@pytest.fixture
def settings() -> Settings:
    """Override the conftest `settings` fixture to wire the webhook secret."""
    return build_test_settings(WEBHOOK_SIGNING_SECRET=WEBHOOK_SECRET)


def _webhook_signature(body: bytes) -> str:
    sig = hmac_mod.HMAC(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
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

    @pytest.mark.asyncio
    async def test_expire_lapsed_marks_active_past_due_as_expired(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        """expire_lapsed_subscriptions mutates an active-but-past-due sub to expired.

        Unlike get_subscription_status (a pure read), this writes the status
        back — the row itself must change, not just the computed string.
        """
        sub = Subscription(
            user_id=regular_user.id,
            plan=SubscriptionPlan.trial,
            status=SubscriptionStatus.active,
            starts_at=datetime.now(UTC) - timedelta(days=15),
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add(sub)
        await db_session.commit()

        await sub_svc.expire_lapsed_subscriptions(db_session, regular_user.id)
        await db_session.commit()

        refreshed = await sub_svc.get_current_subscription(db_session, regular_user.id)
        assert refreshed is not None
        assert refreshed.status == SubscriptionStatus.expired

    @pytest.mark.asyncio
    async def test_expire_lapsed_leaves_active_in_date_untouched(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        """An active subscription not yet past expires_at must stay active."""
        sub = Subscription(
            user_id=regular_user.id,
            plan=SubscriptionPlan.researcher,
            status=SubscriptionStatus.active,
            starts_at=datetime.now(UTC) - timedelta(days=1),
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        db_session.add(sub)
        await db_session.commit()

        await sub_svc.expire_lapsed_subscriptions(db_session, regular_user.id)
        await db_session.commit()

        refreshed = await sub_svc.get_current_subscription(db_session, regular_user.id)
        assert refreshed is not None
        assert refreshed.status == SubscriptionStatus.active

    @pytest.mark.asyncio
    async def test_expire_lapsed_noop_when_no_subscription(
        self, db_session: AsyncSession, regular_user: User
    ) -> None:
        """expire_lapsed_subscriptions must not raise for a user with no subscription."""
        await sub_svc.expire_lapsed_subscriptions(db_session, regular_user.id)
        await db_session.commit()
        assert await sub_svc.get_current_subscription(db_session, regular_user.id) is None


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
    async def test_no_subscription_returns_404(self, client: AsyncClient, admin_user: User) -> None:
        resp = await client.get(
            f"/api/v1/subscriptions/{uuid.uuid4()}",
            headers=_auth_header(admin_user),
        )
        assert resp.status_code == 404


class TestWebhook:
    @pytest.mark.asyncio
    async def test_subscription_created(self, client: AsyncClient, regular_user: User) -> None:
        payload = json.dumps(
            {
                "event_type": "subscription.created",
                "user_id": str(regular_user.id),
                "plan": "researcher",
            }
        ).encode()
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
    async def test_unknown_event_ignored(self, client: AsyncClient, regular_user: User) -> None:
        payload = json.dumps(
            {
                "event_type": "invoice.paid",
                "user_id": str(regular_user.id),
            }
        ).encode()
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
        payload = json.dumps(
            {
                "event_type": "subscription.created",
                "user_id": str(regular_user.id),
                "plan": "researcher",
            }
        ).encode()
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
        await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        payload = json.dumps(
            {
                "event_type": "subscription.cancelled",
                "user_id": str(regular_user.id),
            }
        ).encode()
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
        await sub_svc.create_subscription(db_session, regular_user.id, "researcher")
        await db_session.commit()
        payload = json.dumps(
            {
                "event_type": "subscription.updated",
                "user_id": str(regular_user.id),
                "status": "suspended",
                "plan": "institutional",
            }
        ).encode()
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
        payload = json.dumps(
            {
                "event_type": "subscription.updated",
                "user_id": str(regular_user.id),
                "status": "bogus_status",
            }
        ).encode()
        resp = await client.post(
            "/api/v1/subscriptions/webhook",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _webhook_signature(payload),
            },
        )
        assert resp.status_code == 422
