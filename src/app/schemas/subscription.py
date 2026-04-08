"""Subscription schemas — US #9."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class SubscriptionCreate(BaseModel):
    """Create or update a subscription for a user."""

    user_id: uuid.UUID
    plan: str = Field(pattern=r"^(free|trial|researcher|institutional)$")
    status: str = Field(default="active", pattern=r"^(active|expired|cancelled|suspended)$")

    model_config = {"frozen": True}


class TrialStartRequest(BaseModel):
    """Start a trial for the current user."""

    model_config = {"frozen": True}


class SubscriptionRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    plan: str
    status: str
    starts_at: datetime
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class WebhookEvent(BaseModel):
    """Webhook payload from an external payment provider."""

    event_type: str
    user_id: uuid.UUID
    plan: str | None = None
    status: str | None = None

    model_config = {"frozen": True}
