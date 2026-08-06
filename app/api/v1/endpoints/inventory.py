"""Network inventory: software packages na discovery schedules.

- GET  /software                    -> programu zilizogunduliwa kwenye hosts
- GET  /discovery/schedules         -> ratiba za discovery sweep
- POST /discovery/schedules         -> panga discovery ya kiotomatiki
- DELETE /discovery/schedules/{id}  -> futa ratiba
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import Field, field_serializer

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.crud import agent as agent_crud
from app.crud import inventory as crud
from app.schemas.common import CamelModel, Message

router = APIRouter(tags=["inventory"])

Frequency = Literal["hourly", "daily", "weekly"]


class SoftwarePackageRead(CamelModel):
    id: uuid.UUID
    host: str
    name: str
    version: str
    publisher: str
    created_at: datetime

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class DiscoveryScheduleRead(CamelModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    subnet: str
    frequency: Frequency
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None = None

    @field_serializer("id", "agent_id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class DiscoveryScheduleCreate(CamelModel):
    agent_id: uuid.UUID
    subnet: str = Field(default="", max_length=64)
    frequency: Frequency = "daily"


@router.get("/software", response_model=list[SoftwarePackageRead], summary="Installed software across hosts")
async def list_software(
    user: CurrentUser,
    db: DbSession,
    host: Annotated[str | None, Query()] = None,
) -> list[SoftwarePackageRead]:
    rows = await crud.list_software(db, user.organization_id, host=host)
    return [SoftwarePackageRead.model_validate(p) for p in rows]


@router.get("/discovery/schedules", response_model=list[DiscoveryScheduleRead], summary="List discovery schedules")
async def list_schedules(user: CurrentUser, db: DbSession) -> list[DiscoveryScheduleRead]:
    rows = await crud.list_schedules(db, user.organization_id)
    return [DiscoveryScheduleRead.model_validate(s) for s in rows]


@router.post("/discovery/schedules", response_model=DiscoveryScheduleRead, summary="Schedule automatic discovery")
async def create_schedule(
    payload: DiscoveryScheduleCreate, user: RequireAnalyst, db: DbSession
) -> DiscoveryScheduleRead:
    agent = await agent_crud.get_agent(db, user.organization_id, payload.agent_id)
    if agent is None:
        raise NotFoundError("No such agent.", code="agent_not_found")
    sched = await crud.create_schedule(
        db,
        user.organization_id,
        agent_id=payload.agent_id,
        subnet=payload.subnet,
        frequency=payload.frequency,
    )
    return DiscoveryScheduleRead.model_validate(sched)


@router.delete("/discovery/schedules/{schedule_id}", response_model=Message, summary="Delete a discovery schedule")
async def delete_schedule(schedule_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    sched = await crud.get_schedule(db, user.organization_id, schedule_id)
    if sched is None:
        raise NotFoundError("No such schedule.", code="schedule_not_found")
    await crud.delete_schedule(db, sched)
    return Message(detail="Discovery schedule removed.", code="discovery_schedule_deleted")
