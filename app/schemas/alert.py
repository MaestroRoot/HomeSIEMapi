"""Schemas za alerts (lifecycle + SLA)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["new", "acknowledged", "assigned", "snoozed", "resolved"]


class AlertEntity(CamelModel):
    type: str
    value: str
    label: str | None = None


class AlertRead(CamelModel):
    id: uuid.UUID
    rule_id: str | None = None
    incident_id: str | None = None
    title: str
    description: str = ""
    severity: Severity
    status: AlertStatus
    assignee: str | None = None
    snoozed_until: datetime | None = None
    sla_due_at: datetime | None = None
    event_count: int = 1
    first_seen_at: datetime
    last_seen_at: datetime
    entities: list[AlertEntity] = []
    event_ids: list[str] = []
    is_false_positive: bool = False
    resolved_at: datetime | None = None
    resolution_note: str | None = None
    created_at: datetime
    updated_at: datetime

    @field_serializer("id", "rule_id", "incident_id")
    def _u(self, v: uuid.UUID | str | None) -> str | None:
        return str(v) if v else None


class AlertList(CamelModel):
    items: list[AlertRead]
    total: int


class AlertUpdate(CamelModel):
    """Sasisha lifecycle ya alert. Ukiweka `snooze_minutes`, alert inawekwa
    "snoozed" hadi wakati huo; ukiweka `status`, inabadilishwa moja kwa moja."""

    status: AlertStatus | None = None
    assignee: str | None = Field(default=None, max_length=120)
    snooze_minutes: int | None = Field(default=None, ge=1, le=525600)
    resolution_note: str | None = Field(default=None, max_length=2000)


class AlertCounts(CamelModel):
    open: int
    new: int
    acknowledged: int
    assigned: int
    snoozed: int
    resolved_24h: int
    overdue: int
