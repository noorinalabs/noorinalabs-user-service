import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


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

    model_config = {"from_attributes": True}
