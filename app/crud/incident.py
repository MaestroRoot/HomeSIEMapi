"""CRUD ya incidents."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.monitoring import Incident


async def list_incidents(db: AsyncSession, organization_id: uuid.UUID) -> list[Incident]:
    stmt = (
        select(Incident)
        .where(Incident.organization_id == organization_id)
        .order_by(Incident.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def get_incident(
    db: AsyncSession, organization_id: uuid.UUID, incident_id: uuid.UUID
) -> Incident | None:
    stmt = select(Incident).where(
        Incident.id == incident_id, Incident.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_incident(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    title: str,
    severity: str,
    summary: str,
    assignee: str | None,
) -> Incident:
    inc = Incident(
        organization_id=organization_id,
        title=title.strip(),
        severity=severity,
        summary=summary,
        assignee=assignee,
        status="new",
        notes=[],
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)
    return inc


async def update_incident(
    db: AsyncSession,
    inc: Incident,
    *,
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    summary: str | None = None,
    note: str | None = None,
    note_author: str = "system",
) -> Incident:
    if status is not None:
        inc.status = status
    if severity is not None:
        inc.severity = severity
    if assignee is not None:
        inc.assignee = assignee or None
    if summary is not None:
        inc.summary = summary
    if note:
        inc.notes = [
            *inc.notes,
            {
                "author": note_author,
                "time": datetime.now(timezone.utc).isoformat(),
                "body": note.strip(),
            },
        ]
        flag_modified(inc, "notes")
    await db.commit()
    await db.refresh(inc)
    return inc


async def count_open(db: AsyncSession, organization_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count(Incident.id)).where(
                Incident.organization_id == organization_id, Incident.status != "closed"
            )
        )
        or 0
    )
