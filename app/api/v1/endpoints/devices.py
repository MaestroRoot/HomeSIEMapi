"""Devices, matukio, na sensor tokens (upande wa mtumiaji/dashboard)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst, RequireOwner
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.crud import monitoring as crud
from app.schemas.common import CamelModel, Message
from app.schemas.monitoring import (
    DeviceList,
    DeviceRead,
    DeviceRegister,
    DeviceUpdate,
    EventList,
    SecurityEventRead,
    SensorTokenCreate,
    SensorTokenCreated,
    SensorTokenRead,
)


class SearchResults(CamelModel):
    query: str
    events: list[SecurityEventRead]
    devices: list[DeviceRead]
    breakdown: dict[str, int] = {}
    took_ms: float = 0.0

logger = get_logger(__name__)

router = APIRouter(tags=["monitoring"])


# --- Devices --------------------------------------------------------------


@router.get("/devices", response_model=DeviceList, summary="List monitored devices")
async def list_devices(user: CurrentUser, db: DbSession) -> DeviceList:
    rows, total = await crud.list_devices(db, user.organization_id)
    return DeviceList(items=[DeviceRead.model_validate(d) for d in rows], total=total)


@router.post("/devices", response_model=DeviceRead, summary="Register a device")
async def register_device(
    payload: DeviceRegister, user: RequireAnalyst, db: DbSession
) -> DeviceRead:
    device = await crud.register_device(
        db,
        user.organization_id,
        name=payload.name.strip(),
        mac=payload.mac,
        device_type=payload.device_type,
        last_ip=payload.last_ip,
        hostname=payload.hostname,
        owner_name=payload.owner_name,
    )
    return DeviceRead.model_validate(device)


@router.patch("/devices/{device_id}", response_model=DeviceRead, summary="Update a device")
async def update_device(
    device_id: uuid.UUID, payload: DeviceUpdate, user: RequireAnalyst, db: DbSession
) -> DeviceRead:
    device = await crud.get_device(db, user.organization_id, device_id)
    if device is None:
        raise NotFoundError("No such device.", code="device_not_found")
    device = await crud.update_device(
        db,
        device,
        name=payload.name,
        device_type=payload.device_type,
        status=payload.status,
        tags=payload.tags,
        owner_name=payload.owner_name,
    )
    return DeviceRead.model_validate(device)


@router.delete("/devices/{device_id}", response_model=Message, summary="Delete a device")
async def delete_device(device_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    device = await crud.get_device(db, user.organization_id, device_id)
    if device is None:
        raise NotFoundError("No such device.", code="device_not_found")
    await crud.delete_device(db, device)
    logger.info("Device %s imefutwa na %s", device_id, user.email)
    return Message(detail="Device removed.", code="device_deleted")


# --- Matukio --------------------------------------------------------------


@router.get("/events", response_model=EventList, summary="Recent security events")
async def list_events(
    user: CurrentUser,
    db: DbSession,
    only_flagged: Annotated[bool, Query(alias="onlyFlagged")] = False,
    kind: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> EventList:
    rows, total = await crud.list_events(
        db, user.organization_id, limit=limit, only_flagged=only_flagged, kind=kind
    )
    items = []
    for event, device_name in rows:
        read = SecurityEventRead.model_validate(event)
        read.device_name = device_name
        items.append(read)
    return EventList(items=items, total=total)


@router.get(
    "/search",
    response_model=SearchResults,
    summary="Search events and devices (query language)",
)
async def search(
    user: CurrentUser,
    db: DbSession,
    q: Annotated[str, Query(min_length=1, max_length=200)],
) -> SearchResults:
    from app.core.querylang import parse

    parsed = parse(q)
    events, devices, breakdown, took = await crud.siem_search(db, user.organization_id, parsed)
    items = []
    for event, device_name in events:
        read = SecurityEventRead.model_validate(event)
        read.device_name = device_name
        items.append(read)
    return SearchResults(
        query=q,
        events=items,
        devices=[DeviceRead.model_validate(d) for d in devices],
        breakdown={k: int(v) for k, v in breakdown.items()},
        took_ms=round(took, 2),
    )


# --- Sensor tokens (owner pekee) ------------------------------------------


@router.get("/sensors/tokens", response_model=list[SensorTokenRead], summary="List sensor tokens")
async def list_sensor_tokens(user: RequireOwner, db: DbSession) -> list[SensorTokenRead]:
    rows = await crud.list_sensor_tokens(db, user.organization_id)
    return [SensorTokenRead.model_validate(r) for r in rows]


@router.post(
    "/sensors/tokens",
    response_model=SensorTokenCreated,
    summary="Create a sensor token (shown once)",
)
async def create_sensor_token(
    payload: SensorTokenCreate, user: RequireOwner, db: DbSession
) -> SensorTokenCreated:
    row, plaintext = await crud.create_sensor_token(db, user.organization_id, payload.label)
    logger.info("Sensor token '%s' imetengenezwa na %s", payload.label, user.email)
    return SensorTokenCreated(
        id=row.id,
        label=row.label,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
        token=plaintext,
    )
