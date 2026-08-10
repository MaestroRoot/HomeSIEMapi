"""Schemas za detection rules."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

ConditionType = Literal["verdict_is", "domain_contains", "country_is", "pulse_count_gte", "kind_is"]
Severity = Literal["critical", "high", "medium", "low"]
Action = Literal["alert", "log"]


class RuleRead(CamelModel):
    id: uuid.UUID
    name: str
    description: str = ""
    enabled: bool
    condition_type: ConditionType
    value: str
    severity: Severity
    action: Action
    source: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    window_seconds: int = 0
    group_by: str = ""
    threshold: int = 1
    hits: int
    false_positives: int = 0
    last_hit_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid(self, v: uuid.UUID) -> str:
        return str(v)


class RuleCreate(CamelModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    condition_type: ConditionType
    value: str = Field(min_length=1, max_length=255)
    severity: Severity = "medium"
    action: Action = "alert"
    mitre_tactic: str | None = Field(default=None, max_length=64)
    mitre_technique: str | None = Field(default=None, max_length=64)
    window_seconds: int = Field(default=0, ge=0, le=86400)
    group_by: str = Field(default="", max_length=32)
    threshold: int = Field(default=1, ge=1, le=100000)


class RuleUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    value: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    action: Action | None = None
    mitre_tactic: str | None = Field(default=None, max_length=64)
    mitre_technique: str | None = Field(default=None, max_length=64)
    window_seconds: int | None = Field(default=None, ge=0, le=86400)
    group_by: str | None = Field(default=None, max_length=32)
    threshold: int | None = Field(default=None, ge=1, le=100000)
