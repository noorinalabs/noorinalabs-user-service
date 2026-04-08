"""Verification schemas — US #8."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class VerificationSendRequest(BaseModel):
    """Request to send a verification email."""

    model_config = ConfigDict(frozen=True)

    email: EmailStr


class VerificationSendResponse(BaseModel):
    """Response after sending a verification email."""

    model_config = ConfigDict(frozen=True)

    message: str


class VerificationConfirmRequest(BaseModel):
    """Request to confirm an email verification token."""

    model_config = ConfigDict(frozen=True)

    token: str


class VerificationConfirmResponse(BaseModel):
    """Response after confirming email verification."""

    model_config = ConfigDict(frozen=True)

    message: str
    email_verified: bool


class VerificationStatusResponse(BaseModel):
    """Response for email verification status check."""

    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    email: str
    email_verified: bool
    verification_sent_at: datetime | None = None
