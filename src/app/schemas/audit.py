"""Audit log request/response schemas — user-service#200.

The pagination envelope is page/limit/total (offset-based) rather than the
cursor envelope used by ``/api/v1/users``: the isnad-graph admin frontend
(consumer sibling isnad-graph#1140) already renders an offset-paginated audit
table, so this shape matches what it consumes verbatim.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AuditLogCreate(BaseModel):
    """Body for ``POST /api/v1/audit`` — a single audit entry to record."""

    action: str = Field(min_length=1)
    actor_id: uuid.UUID
    actor_name: str = ""
    target_user_id: uuid.UUID | None = None
    details: str = ""

    model_config = {"frozen": True}


class AuditLogRead(BaseModel):
    """A single persisted audit entry (response shape)."""

    id: uuid.UUID
    action: str
    actor_id: uuid.UUID
    actor_name: str
    target_user_id: uuid.UUID | None
    details: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    """Offset-paginated envelope for ``GET /api/v1/audit``."""

    items: list[AuditLogRead]
    total: int
    page: int
    limit: int

    model_config = {"frozen": True}
