"""CRUD ya report schedules + logic ya wakati unaofuata."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import ReportSchedule

_DELTA = {"daily": timedelta(days=1), "weekly": timedelta(days=7), "monthly": timedelta(days=30)}


def next_run(frequency: str, *, frm: datetime | None = None) -> datetime:
    base = frm or datetime.now(timezone.utc)
    return base + _DELTA.get(frequency, timedelta(days=7))


async def list_schedules(db: AsyncSession, org_id: uuid.UUID) -> list[ReportSchedule]:
    stmt = (
        select(ReportSchedule)
        .where(ReportSchedule.organization_id == org_id)
        .order_by(ReportSchedule.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def create_schedule(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    kind: str,
    frequency: str,
    to_whole_team: bool,
    recipients: list[str],
) -> ReportSchedule:
    sched = ReportSchedule(
        organization_id=org_id,
        kind=kind,
        frequency=frequency,
        to_whole_team=to_whole_team,
        recipients=[r.strip() for r in recipients if r.strip()],
        next_run_at=next_run(frequency),
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    return sched


async def get_schedule(db: AsyncSession, org_id: uuid.UUID, sched_id: uuid.UUID) -> ReportSchedule | None:
    return (
        await db.execute(
            select(ReportSchedule).where(
                ReportSchedule.id == sched_id, ReportSchedule.organization_id == org_id
            )
        )
    ).scalar_one_or_none()


async def delete_schedule(db: AsyncSession, sched: ReportSchedule) -> None:
    await db.delete(sched)
    await db.commit()


async def due_schedules(db: AsyncSession) -> list[ReportSchedule]:
    """Ratiba zote (org zote) zilizofikia wakati wake, kwa worker."""
    now = datetime.now(timezone.utc)
    stmt = select(ReportSchedule).where(
        ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at <= now
    )
    return list((await db.execute(stmt)).scalars())


async def mark_ran(db: AsyncSession, sched: ReportSchedule) -> None:
    now = datetime.now(timezone.utc)
    sched.last_run_at = now
    sched.next_run_at = next_run(sched.frequency, frm=now)
    await db.commit()
