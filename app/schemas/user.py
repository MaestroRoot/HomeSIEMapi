import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_serializer

from app.models.enums import Plan, Role
from app.schemas.common import CamelModel


class UserRead(CamelModel):
    """Umbo hili linalingana na interface `User` ya frontend (AuthContext.tsx)."""

    id: uuid.UUID
    name: str
    email: EmailStr
    role: Role
    plan: Plan
    mfa_enabled: bool
    email_verified: bool
    avatar_url: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
    organization_id: uuid.UUID

    @field_serializer("id", "organization_id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class UserUpdate(CamelModel):
    """Kile mtumiaji anaruhusiwa kubadilisha kwenye profile yake mwenyewe."""

    name: str | None = Field(default=None, min_length=2, max_length=120)
    avatar_url: str | None = Field(default=None, max_length=512)
    mfa_enabled: bool | None = None


class UserRoleUpdate(CamelModel):
    """Owner pekee ndiye anaweza kubadilisha role ya mtu mwingine."""

    role: Role


class UserList(CamelModel):
    items: list[UserRead]
    total: int
