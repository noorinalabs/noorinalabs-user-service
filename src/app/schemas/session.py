"""Session schemas — US #7."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SessionResponse(BaseModel):
    """A single session record."""

    model_config = ConfigDict(frozen=True, from_attributes=True)

    id: uuid.UUID
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime
    last_active: datetime
    expires_at: datetime
    is_current: bool = False


class SessionListResponse(BaseModel):
    """List of active sessions for the current user."""

    model_config = ConfigDict(frozen=True)

    sessions: list[SessionResponse]
    count: int


class SessionCreateResponse(BaseModel):
    """Response after creating a session."""

    model_config = ConfigDict(frozen=True)

    session_id: uuid.UUID
    refresh_token: str
    expires_at: datetime


class RevokeAllResponse(BaseModel):
    """Response after revoking all sessions."""

    model_config = ConfigDict(frozen=True)

    revoked_count: int
