"""Schemas za logs, vulnerabilities na forensics (read + ingest)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel


# --- Logs -----------------------------------------------------------------


class LogIn(CamelModel):
    source: str = Field(max_length=64)
    host: str | None = Field(default=None, max_length=120)
    level: str = Field(default="info", max_length=16)
    message: str = Field(max_length=8000)
    ts: float | None = None


class LogBatch(CamelModel):
    entries: list[LogIn] = Field(min_length=1, max_length=500)


class LogRead(CamelModel):
    id: uuid.UUID
    source: str
    host: str | None = None
    level: str
    message: str
    occurred_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


# --- Vulnerabilities ------------------------------------------------------


class VulnFinding(CamelModel):
    port: int | None = None
    service: str | None = None
    severity: str = "info"
    title: str = Field(max_length=200)
    detail: str = ""
    fix: str = ""


class ScanResult(CamelModel):
    target: str = Field(max_length=45)
    findings: list[VulnFinding] = Field(default_factory=list, max_length=200)


class VulnRead(CamelModel):
    id: uuid.UUID
    target: str
    port: int | None = None
    service: str | None = None
    severity: str
    title: str
    detail: str
    fix: str
    status: str = "open"
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class VulnStatusUpdate(CamelModel):
    status: str = Field(max_length=16)


# --- Forensics ------------------------------------------------------------


class ForensicIn(CamelModel):
    host: str = Field(max_length=120)
    processes: list[dict] = Field(default_factory=list, max_length=1000)
    connections: list[dict] = Field(default_factory=list, max_length=1000)


class ForensicRead(CamelModel):
    id: uuid.UUID
    host: str
    processes: list[dict]
    connections: list[dict]
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)
