"""Schemas za SOAR response actions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

ActionKind = Literal["isolate", "block", "disable", "snapshot", "notify"]
ActionStatus = Literal["pending", "running", "succeeded", "failed", "manual"]


class ActionRead(CamelModel):
    id: uuid.UUID
    incident_id: str | None = None
    alert_id: str | None = None
    kind: ActionKind
    target_type: str
    target: str
    params: dict = {}
    status: ActionStatus
    result: dict | None = None
    error: str | None = None
    executed_at: datetime | None = None
    created_at: datetime

    @field_serializer("id", "incident_id", "alert_id")
    def _u(self, v: uuid.UUID | str | None) -> str | None:
        return str(v) if v else None


class ActionCreate(CamelModel):
    kind: ActionKind
    target_type: str = Field(default="", max_length=24)
    target: str = Field(min_length=1, max_length=255)
    params: dict = Field(default_factory=dict)
    incident_id: str | None = None
    alert_id: str | None = None


class ActionList(CamelModel):
    items: list[ActionRead]
    total: int


class ActionStatusUpdate(CamelModel):
    status: ActionStatus
    result: dict | None = None
    error: str | None = Field(default=None, max_length=1000)
