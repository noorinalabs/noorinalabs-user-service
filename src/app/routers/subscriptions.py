"""Subscription routes — US #9."""

from __future__ import annotations

import hashlib
import hmac
import uuid

from fastapi import APIRouter, Header, HTTPException, Request, status

from src.app.dependencies import AdminUserDep, CurrentUserDep, DbDep, SettingsDep
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


@router.delete("/me", response_model=SubscriptionRead)
async def cancel_my_subscription(
    current_user: CurrentUserDep,
    db: DbDep,
) -> SubscriptionRead:
    """Cancel the current user's active subscription."""
    sub = await sub_svc.cancel_subscription(db, current_user.id)
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active subscription to cancel",
        )
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


def _verify_webhook_signature(
    body: bytes, signature: str, secret: str
) -> bool:
    """Verify HMAC-SHA256 webhook signature."""
    expected = hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def payment_webhook(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    x_webhook_signature: str = Header(),
) -> dict[str, str]:
    """Webhook endpoint for payment provider callbacks.

    Requires HMAC-SHA256 signature in X-Webhook-Signature header.
    """
    if not settings.WEBHOOK_SIGNING_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook signing secret not configured",
        )

    raw_body = await request.body()
    if not _verify_webhook_signature(
        raw_body, x_webhook_signature, settings.WEBHOOK_SIGNING_SECRET
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )

    body = WebhookEvent.model_validate_json(raw_body)
    try:
        result = await sub_svc.handle_webhook_event(
            db,
            user_id=body.user_id,
            event_type=body.event_type,
            plan=body.plan,
            status=body.status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    await db.commit()
    if result is None:
        return {"status": "ignored"}
    return {"status": "processed"}
