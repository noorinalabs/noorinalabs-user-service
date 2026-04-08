"""Subscription routes — US #9."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status

from src.app.dependencies import AdminUserDep, CurrentUserDep, DbDep
from src.app.schemas.subscription import (
    SubscriptionCreate,
    SubscriptionRead,
    TrialStartRequest,
    WebhookEvent,
)
from src.app.services import subscription as sub_svc

router = APIRouter(prefix="/api/v1/subscriptions", tags=["subscriptions"])


@router.get("/me", response_model=SubscriptionRead)
async def get_my_subscription(
    current_user: CurrentUserDep,
    db: DbDep,
) -> SubscriptionRead:
    """Get the current user's subscription."""
    sub = await sub_svc.get_current_subscription(db, current_user.id)
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No subscription found",
        )
    return SubscriptionRead.model_validate(sub)


@router.post("", response_model=SubscriptionRead, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    body: SubscriptionCreate,
    _admin: AdminUserDep,
    db: DbDep,
) -> SubscriptionRead:
    """Create or update a subscription (admin only)."""
    sub = await sub_svc.create_subscription(
        db, user_id=body.user_id, plan=body.plan, status=body.status
    )
    await db.commit()
    return SubscriptionRead.model_validate(sub)


@router.post("/trial", response_model=SubscriptionRead, status_code=status.HTTP_201_CREATED)
async def start_trial(
    _body: TrialStartRequest,
    current_user: CurrentUserDep,
    db: DbDep,
) -> SubscriptionRead:
    """Start a 14-day trial for the current user."""
    try:
        sub = await sub_svc.start_trial(db, current_user.id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    await db.commit()
    return SubscriptionRead.model_validate(sub)


@router.get("/{user_id}", response_model=SubscriptionRead)
async def get_user_subscription(
    user_id: uuid.UUID,
    _admin: AdminUserDep,
    db: DbDep,
) -> SubscriptionRead:
    """Admin: view a specific user's subscription."""
    sub = await sub_svc.get_current_subscription(db, user_id)
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No subscription found",
        )
    return SubscriptionRead.model_validate(sub)


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def payment_webhook(
    body: WebhookEvent,
    db: DbDep,
) -> dict[str, str]:
    """Webhook endpoint for payment provider callbacks."""
    result = await sub_svc.handle_webhook_event(
        db,
        user_id=body.user_id,
        event_type=body.event_type,
        plan=body.plan,
        status=body.status,
    )
    await db.commit()
    if result is None:
        return {"status": "ignored"}
    return {"status": "processed"}
