"""Schemas za incidents."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["new", "triage", "containment", "eradication", "closed"]


class IncidentNote(CamelModel):
    author: str
    time: str
    body: str


class IncidentRead(CamelModel):
    id: uuid.UUID
    title: str
    severity: Severity
    status: Status
    assignee: str | None = None
    summary: str
    notes: list[IncidentNote] = []
    created_at: datetime
    updated_at: datetime

    @field_serializer("id")
    def _uuid(self, v: uuid.UUID) -> str:
        return str(v)


class IncidentCreate(CamelModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Severity = "medium"
    summary: str = Field(default="", max_length=4000)
    assignee: str | None = Field(default=None, max_length=120)


class IncidentUpdate(CamelModel):
    status: Status | None = None
    severity: Severity | None = None
    assignee: str | None = Field(default=None, max_length=120)
    summary: str | None = Field(default=None, max_length=4000)
    #: Ongeza note mpya (body pekee, author/time zinawekwa na server).
    note: str | None = Field(default=None, max_length=2000)
