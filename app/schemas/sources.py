"""Schemas za data sources (source health)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import field_serializer

from app.schemas.common import CamelModel


class SourceRead(CamelModel):
    id: uuid.UUID
    name: str
    type: str
    enabled: bool
    #: healthy | degraded | offline | inactive (imekokotolewa read-time).
    status: str
    last_event_at: datetime | None = None
    last_error: str | None = None
    events_total: int = 0
    #: Matukio ya saa 24 zilizopita (read-time).
    events_24h: int = 0
    #: Matukio ya saa iliyopita (read-time).
    events_1h: int = 0
    #: Matukio kwa sekunde (saa iliyopita / 3600).
    eps: float = 0.0
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class SourceRegister(CamelModel):
    name: str
    type: str = "sensor"
    enabled: bool = True


class SourceUpdate(CamelModel):
    name: str | None = None
    type: str | None = None
    enabled: bool | None = None


class SourceList(CamelModel):
    items: list[SourceRead]
    total: int
