"""Schemas za agents na agent jobs."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

JobKind = Literal["scan", "forensics", "logs", "capture", "discovery", "software"]
JobStatus = Literal["pending", "running", "done", "error"]


# --- agent-facing (host side) ---------------------------------------------


class EnrollRequest(CamelModel):
    hostname: str = Field(max_length=120)
    os: str | None = Field(default=None, max_length=64)
    ip: str | None = Field(default=None, max_length=45)
    capabilities: list[str] = Field(default_factory=list)


class EnrollResponse(CamelModel):
    agent_id: uuid.UUID

    @field_serializer("agent_id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class JobForAgent(CamelModel):
    id: uuid.UUID
    kind: JobKind
    params: dict

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class JobResult(CamelModel):
    status: Literal["done", "error"]
    result: dict | None = None
    error: str | None = None


# --- dashboard-facing -----------------------------------------------------


class AgentRead(CamelModel):
    id: uuid.UUID
    hostname: str
    os: str | None = None
    last_ip: str | None = None
    capabilities: list[str]
    last_seen_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class JobCreate(CamelModel):
    kind: JobKind
    params: dict = Field(default_factory=dict)


class JobRead(CamelModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    kind: JobKind
    status: JobStatus
    params: dict
    result: dict | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime

    @field_serializer("id", "agent_id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)
