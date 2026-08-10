"""SOAR-lite response actions: isolate/block/disable/snapshot/notify."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.crud import actions as crud
from app.schemas.actions import ActionCreate, ActionList, ActionRead, ActionStatusUpdate

router = APIRouter(prefix="/actions", tags=["actions"])


@router.get("", response_model=ActionList, summary="List response actions")
async def list_actions(
    user: CurrentUser,
    db: DbSession,
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ActionList:
    rows, total = await crud.list_actions(
        db, user.organization_id, incident_id=incident_id, limit=limit, offset=offset
    )
    return ActionList(items=[ActionRead.model_validate(r) for r in rows], total=total)


@router.post("", response_model=ActionRead, summary="Create a response action")
async def create_action(payload: ActionCreate, user: RequireAnalyst, db: DbSession) -> ActionRead:
    try:
        action = await crud.create_action(
            db,
            user.organization_id,
            kind=payload.kind,
            target_type=payload.target_type or "device",
            target=payload.target,
            created_by_id=user.id,
            incident_id=uuid.UUID(payload.incident_id) if payload.incident_id else None,
            alert_id=uuid.UUID(payload.alert_id) if payload.alert_id else None,
            params=payload.params,
        )
    except ValueError as exc:
        raise NotFoundError(str(exc), code="invalid_action_kind") from exc
    return ActionRead.model_validate(action)


@router.patch("/{action_id}/status", response_model=ActionRead, summary="Update action status")
async def update_status(
    action_id: uuid.UUID,
    payload: ActionStatusUpdate,
    user: RequireAnalyst,
    db: DbSession,
) -> ActionRead:
    action = await crud.get_action(db, user.organization_id, action_id)
    if action is None:
        raise NotFoundError("No such action.", code="action_not_found")
    action = await crud.update_action_status(
        db, action, status=payload.status, result=payload.result, error=payload.error
    )
    return ActionRead.model_validate(action)
