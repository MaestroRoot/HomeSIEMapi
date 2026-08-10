"""CRUD ya SOAR-lite response actions (isolate/block/disable/snapshot/notify)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.siem import ResponseAction

_ALLOWED_KINDS = ("isolate", "block", "disable", "snapshot", "notify")

#: Actions zilizoachwa pending hadi mwanzo wa siku ya sasa ni "stale".
_STALE_BEFORE = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


async def create_action(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    kind: str,
    target_type: str,
    target: str,
    created_by_id: uuid.UUID | None,
    incident_id: uuid.UUID | None = None,
    alert_id: uuid.UUID | None = None,
    params: dict | None = None,
) -> ResponseAction:
    if kind not in _ALLOWED_KINDS:
        raise ValueError(f"kind isiyotambulika: {kind}")
    action = ResponseAction(
        organization_id=organization_id,
        incident_id=incident_id,
        alert_id=alert_id,
        created_by_id=created_by_id,
        kind=kind,
        target_type=target_type,
        target=target.strip()[:255],
        params=params or {},
        status="pending",
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


async def list_actions(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    incident_id: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[ResponseAction], int]:
    stmt = select(ResponseAction).where(ResponseAction.organization_id == organization_id)
    count_stmt = select(func.count(ResponseAction.id)).where(
        ResponseAction.organization_id == organization_id
    )
    if incident_id is not None:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
        count_stmt = count_stmt.where(ResponseAction.incident_id == incident_id)
    stmt = stmt.order_by(ResponseAction.created_at.desc()).limit(limit).offset(offset)
    total = int(await db.scalar(count_stmt) or 0)
    return list((await db.execute(stmt)).scalars()), total


async def get_action(
    db: AsyncSession, organization_id: uuid.UUID, action_id: uuid.UUID
) -> ResponseAction | None:
    stmt = select(ResponseAction).where(
        ResponseAction.id == action_id, ResponseAction.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def update_action_status(
    db: AsyncSession,
    action: ResponseAction,
    *,
    status: str,
    result: dict | None = None,
    error: str | None = None,
) -> ResponseAction:
    action.status = status
    if result is not None:
        action.result = result
    if error is not None:
        action.error = error[:1000]
    if status in ("succeeded", "failed") and action.executed_at is None:
        action.executed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(action)
    return action


async def mark_stale_pending(db: AsyncSession, organization_id: uuid.UUID) -> int:
    """Actions zilizoachwa pending (sensor haikukiri) zinahitaji review ya
    mwanadamu. Inarudisha idadi iliyohamishwa kuwa 'manual'."""
    rows = list(
        (
            await db.execute(
                select(ResponseAction).where(
                    ResponseAction.organization_id == organization_id,
                    ResponseAction.status == "pending",
                    ResponseAction.created_at < _STALE_BEFORE,
                )
            )
        ).scalars()
    )
    for row in rows:
        row.status = "manual"
    if rows:
        await db.commit()
    return len(rows)
