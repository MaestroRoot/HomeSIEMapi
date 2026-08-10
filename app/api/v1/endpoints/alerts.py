"""Alerts: lifecycle (ack/assign/snooze/resolve), SLA, noise reduction."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.crud import alerts as crud
from app.schemas.alert import AlertCounts, AlertList, AlertRead, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertList, summary="List alerts (filter by status/severity)")
async def list_alerts(
    user: CurrentUser,
    db: DbSession,
    status: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertList:
    rows, total = await crud.list_alerts(
        db, user.organization_id, status=status, severity=severity, limit=limit, offset=offset
    )
    return AlertList(items=[AlertRead.model_validate(r) for r in rows], total=total)


@router.get("/counts", response_model=AlertCounts, summary="Alert lifecycle counts")
async def counts(user: CurrentUser, db: DbSession) -> AlertCounts:
    return AlertCounts(**await crud.alert_counts(db, user.organization_id))


@router.patch("/{alert_id}", response_model=AlertRead, summary="Update alert lifecycle")
async def update_alert(
    alert_id: uuid.UUID, payload: AlertUpdate, user: RequireAnalyst, db: DbSession
) -> AlertRead:
    alert = await crud.get_alert(db, user.organization_id, alert_id)
    if alert is None:
        raise NotFoundError("No such alert.", code="alert_not_found")
    if payload.status is not None:
        status = payload.status
    elif payload.snooze_minutes is not None:
        status = "snoozed"
    else:
        status = alert.status
    alert = await crud.set_status(
        db,
        alert,
        status,
        assignee=payload.assignee,
        snooze_minutes=payload.snooze_minutes,
        note=payload.resolution_note,
    )
    return AlertRead.model_validate(alert)
