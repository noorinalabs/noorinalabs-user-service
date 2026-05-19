import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, EmailStr, Field


class RoleName(StrEnum):
    """Canonical role names exposed in the public API.

    Source of truth: `role_hierarchy` in `ontology/repos/user-service.yaml`
    and the seed data created by migration 0001. Renames or additions must
    go through cross-repo coordination (us#103, main#161).
    """

    admin = "admin"
    researcher = "researcher"
    reader = "reader"
    trial = "trial"


class UserBase(BaseModel):
    email: EmailStr
    display_name: str | None = None


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: uuid.UUID
    email_verified: bool
    avatar_url: str | None
    locale: str | None
    is_active: bool
    created_at: datetime
    roles: list[RoleName] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    display_name: str | None = None
    avatar_url: str | None = None
    locale: str | None = None

    model_config = {"frozen": True}


class UserListResponse(BaseModel):
    items: list[UserRead]
    next_cursor: str | None = None

    model_config = {"frozen": True}


class RoleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleAssignment(BaseModel):
    role_id: uuid.UUID

    model_config = {"frozen": True}
