"""Notification channels: orodha, unda, futa, jaribu."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter
from pydantic import Field, field_serializer

from datetime import datetime

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core import notify
from app.core.errors import AppError, NotFoundError
from app.crud import notification as crud
from app.schemas.common import CamelModel, Message

router = APIRouter(prefix="/notifications", tags=["notifications"])

ChannelType = Literal["slack", "discord", "email", "webhook", "pagerduty"]


class ChannelRead(CamelModel):
    id: uuid.UUID
    type: ChannelType
    name: str
    target: str
    min_severity: str
    enabled: bool
    last_sent_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class ChannelCreate(CamelModel):
    type: ChannelType
    name: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=1024)
    min_severity: Literal["critical", "high", "medium", "low"] = "high"


@router.get("/channels", response_model=list[ChannelRead], summary="List notification channels")
async def list_channels(user: CurrentUser, db: DbSession) -> list[ChannelRead]:
    rows = await crud.list_channels(db, user.organization_id)
    return [ChannelRead.model_validate(c) for c in rows]


@router.post("/channels", response_model=ChannelRead, summary="Add a notification channel")
async def create_channel(payload: ChannelCreate, user: RequireAnalyst, db: DbSession) -> ChannelRead:
    ch = await crud.create_channel(
        db,
        user.organization_id,
        type=payload.type,
        name=payload.name,
        target=payload.target,
        min_severity=payload.min_severity,
    )
    return ChannelRead.model_validate(ch)


@router.delete("/channels/{channel_id}", response_model=Message, summary="Delete a channel")
async def delete_channel(channel_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    ch = await crud.get_channel(db, user.organization_id, channel_id)
    if ch is None:
        raise NotFoundError("No such channel.", code="channel_not_found")
    await crud.delete_channel(db, ch)
    return Message(detail="Channel removed.", code="channel_deleted")


@router.post("/channels/{channel_id}/test", response_model=Message, summary="Send a test notification")
async def test_channel(channel_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    ch = await crud.get_channel(db, user.organization_id, channel_id)
    if ch is None:
        raise NotFoundError("No such channel.", code="channel_not_found")
    ok = await notify.send_alert(
        ch_type=ch.type,
        target=ch.target,
        subject="HomeSIEM test notification",
        message="If you can read this, this channel is wired up correctly.",
    )
    if not ok:
        raise AppError("The test notification failed to send. Check the target URL/address.", code="notify_failed")
    return Message(detail="Test notification sent.", code="notify_sent")
