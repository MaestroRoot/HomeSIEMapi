"""Data sources: registry + health (source health page)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.crud import sources as crud
from app.schemas.sources import SourceList, SourceRead, SourceRegister, SourceUpdate

router = APIRouter(prefix="/sources", tags=["sources"])


def _to_read(row, stats: dict) -> SourceRead:
    return SourceRead(
        id=row.id,
        name=row.name,
        type=row.type,
        enabled=row.enabled,
        status=crud.source_status(row),
        last_event_at=row.last_event_at,
        last_error=row.last_error,
        events_total=row.events_total or 0,
        events_24h=stats.get("events_24h", 0),
        events_1h=stats.get("events_1h", 0),
        eps=stats.get("eps", 0.0),
        created_at=row.created_at,
    )


@router.get("", response_model=SourceList, summary="List data sources with health")
async def list_sources(user: CurrentUser, db: DbSession) -> SourceList:
    rows = await crud.list_sources(db, user.organization_id)
    return SourceList(
        items=[_to_read(row, stats) for row, stats in rows],
        total=len(rows),
    )


@router.post("", response_model=SourceRead, summary="Register a data source")
async def register_source(
    payload: SourceRegister, user: RequireAnalyst, db: DbSession
) -> SourceRead:
    row = await crud.register_source(
        db,
        user.organization_id,
        name=payload.name,
        type=payload.type,
        enabled=payload.enabled,
    )
    return _to_read(row, {"events_24h": 0, "events_1h": 0, "eps": 0.0})


@router.patch("/{source_id}", response_model=SourceRead, summary="Update a data source")
async def update_source(
    source_id: uuid.UUID, payload: SourceUpdate, user: RequireAnalyst, db: DbSession
) -> SourceRead:
    row = await crud.get_source(db, user.organization_id, source_id)
    if row is None:
        raise NotFoundError("No such source.", code="source_not_found")
    row = await crud.update_source(
        db, row, name=payload.name, type=payload.type, enabled=payload.enabled
    )
    return _to_read(row, {"events_24h": 0, "events_1h": 0, "eps": 0.0})
