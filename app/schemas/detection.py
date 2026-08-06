"""Schemas za detection rules."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

ConditionType = Literal["verdict_is", "domain_contains", "country_is", "pulse_count_gte"]
Severity = Literal["critical", "high", "medium", "low"]
Action = Literal["alert", "log"]


class RuleRead(CamelModel):
    id: uuid.UUID
    name: str
    enabled: bool
    condition_type: ConditionType
    value: str
    severity: Severity
    action: Action
    source: str
    hits: int
    false_positives: int = 0
    last_hit_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid(self, v: uuid.UUID) -> str:
        return str(v)


class RuleCreate(CamelModel):
    name: str = Field(min_length=1, max_length=120)
    condition_type: ConditionType
    value: str = Field(min_length=1, max_length=255)
    severity: Severity = "medium"
    action: Action = "alert"


class RuleUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    value: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    action: Action | None = None
