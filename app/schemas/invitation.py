import uuid
from datetime import datetime

from pydantic import EmailStr, field_serializer

from app.models.enums import InvitationStatus, Role
from app.schemas.common import CamelModel


class InvitationCreate(CamelModel):
    email: EmailStr
    role: Role = Role.VIEWER


class InvitationRead(CamelModel):
    id: uuid.UUID
    email: EmailStr
    role: Role
    status: InvitationStatus
    email_sent: bool
    expires_at: datetime
    accepted_at: datetime | None = None
    created_at: datetime
    invited_by_name: str | None = None

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class InvitationList(CamelModel):
    items: list[InvitationRead]
    total: int
