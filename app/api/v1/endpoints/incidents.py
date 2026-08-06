"""Incidents: unda, orodha, sasisha (status/assignee/notes)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.crud import incident as crud
from app.schemas.incident import IncidentCreate, IncidentRead, IncidentUpdate

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentRead], summary="List incidents")
async def list_incidents(user: CurrentUser, db: DbSession) -> list[IncidentRead]:
    rows = await crud.list_incidents(db, user.organization_id)
    return [IncidentRead.model_validate(r) for r in rows]


@router.post("", response_model=IncidentRead, summary="Open an incident")
async def create_incident(payload: IncidentCreate, user: RequireAnalyst, db: DbSession) -> IncidentRead:
    inc = await crud.create_incident(
        db,
        user.organization_id,
        title=payload.title,
        severity=payload.severity,
        summary=payload.summary,
        assignee=payload.assignee,
    )
    return IncidentRead.model_validate(inc)


@router.patch("/{incident_id}", response_model=IncidentRead, summary="Update an incident")
async def update_incident(
    incident_id: uuid.UUID, payload: IncidentUpdate, user: RequireAnalyst, db: DbSession
) -> IncidentRead:
    inc = await crud.get_incident(db, user.organization_id, incident_id)
    if inc is None:
        raise NotFoundError("No such incident.", code="incident_not_found")
    inc = await crud.update_incident(
        db,
        inc,
        status=payload.status,
        severity=payload.severity,
        assignee=payload.assignee,
        summary=payload.summary,
        note=payload.note,
        note_author=user.name,
    )
    return IncidentRead.model_validate(inc)
