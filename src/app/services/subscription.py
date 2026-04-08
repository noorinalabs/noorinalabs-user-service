"""Subscription service — US #9."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.app.models.subscription import Subscription, SubscriptionPlan, SubscriptionStatus

TRIAL_DURATION_DAYS = 14


async def get_current_subscription(
    db: AsyncSession, user_id: uuid.UUID
) -> Subscription | None:
    """Return the most recent subscription for a user."""
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id)
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_subscription_status(db: AsyncSession, user_id: uuid.UUID) -> str:
    """Return the current subscription status string for JWT claims."""
    sub = await get_current_subscription(db, user_id)
    if sub is None:
        return "free"
    is_expired = (
        sub.status == SubscriptionStatus.active
        and sub.expires_at
        and sub.expires_at < datetime.now(UTC)
    )
    if is_expired:
        sub.status = SubscriptionStatus.expired
        await db.flush()
        return "expired"
    return sub.status.value


async def create_subscription(
    db: AsyncSession,
    user_id: uuid.UUID,
    plan: str,
    status: str = "active",
) -> Subscription:
    """Create a new subscription record."""
    now = datetime.now(UTC)
    subscription = Subscription(
        user_id=user_id,
        plan=SubscriptionPlan(plan),
        status=SubscriptionStatus(status),
        starts_at=now,
    )
    db.add(subscription)
    await db.flush()
    await db.refresh(subscription)
    return subscription


async def start_trial(db: AsyncSession, user_id: uuid.UUID) -> Subscription:
    """Start a 14-day trial. Raises ValueError if user already had a trial."""
    existing = await _has_had_trial(db, user_id)
    if existing:
        raise ValueError("User has already used their trial")

    now = datetime.now(UTC)
    subscription = Subscription(
        user_id=user_id,
        plan=SubscriptionPlan.trial,
        status=SubscriptionStatus.active,
        starts_at=now,
        expires_at=now + timedelta(days=TRIAL_DURATION_DAYS),
    )
    db.add(subscription)
    await db.flush()
    await db.refresh(subscription)
    return subscription


async def cancel_subscription(
    db: AsyncSession, user_id: uuid.UUID
) -> Subscription | None:
    """Cancel the current active subscription."""
    sub = await get_current_subscription(db, user_id)
    if sub is None or sub.status != SubscriptionStatus.active:
        return None
    sub.status = SubscriptionStatus.cancelled
    await db.flush()
    await db.refresh(sub)
    return sub


async def handle_webhook_event(
    db: AsyncSession,
    user_id: uuid.UUID,
    event_type: str,
    plan: str | None = None,
    status: str | None = None,
) -> Subscription | None:
    """Process a payment provider webhook event."""
    if event_type == "subscription.created" and plan:
        return await create_subscription(db, user_id, plan)
    if event_type == "subscription.cancelled":
        return await cancel_subscription(db, user_id)
    if event_type == "subscription.updated" and status:
        sub = await get_current_subscription(db, user_id)
        if sub is not None:
            sub.status = SubscriptionStatus(status)
            if plan:
                sub.plan = SubscriptionPlan(plan)
            await db.flush()
            await db.refresh(sub)
        return sub
    return None


async def _has_had_trial(db: AsyncSession, user_id: uuid.UUID) -> bool:
    """Check if a user has ever had a trial subscription."""
    result = await db.execute(
        select(Subscription.id)
        .where(
            Subscription.user_id == user_id,
            Subscription.plan == SubscriptionPlan.trial,
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None
