"""CRUD ya software inventory na discovery schedules."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import DiscoverySchedule, SoftwarePackage

# --- software packages ----------------------------------------------------

_MAX_PACKAGES = 800


async def replace_for_host(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    host: str,
    device_id: uuid.UUID | None,
    packages: list[dict],
) -> int:
    """Futa software ya zamani ya host huu, weka mpya (delete-then-insert)."""
    await db.execute(
        delete(SoftwarePackage).where(
            SoftwarePackage.organization_id == organization_id, SoftwarePackage.host == host
        )
    )
    added = 0
    for p in packages[:_MAX_PACKAGES]:
        name = (p.get("name") or "").strip()
        if not name:
            continue
        db.add(
            SoftwarePackage(
                organization_id=organization_id,
                host=host,
                device_id=device_id,
                name=name[:200],
                version=(p.get("version") or "")[:60],
                publisher=(p.get("publisher") or "")[:120],
            )
        )
        added += 1
    return added


async def list_software(
    db: AsyncSession, organization_id: uuid.UUID, *, host: str | None = None
) -> list[SoftwarePackage]:
    where = [SoftwarePackage.organization_id == organization_id]
    if host:
        where.append(SoftwarePackage.host == host)
    stmt = (
        select(SoftwarePackage)
        .where(*where)
        .order_by(SoftwarePackage.host, SoftwarePackage.name)
    )
    return list((await db.execute(stmt)).scalars())


# --- discovery schedules --------------------------------------------------

_DELTA = {"hourly": timedelta(hours=1), "daily": timedelta(days=1), "weekly": timedelta(days=7)}


def next_run(frequency: str, *, frm: datetime | None = None) -> datetime:
    base = frm or datetime.now(timezone.utc)
    return base + _DELTA.get(frequency, timedelta(days=1))


async def list_schedules(db: AsyncSession, org_id: uuid.UUID) -> list[DiscoverySchedule]:
    stmt = (
        select(DiscoverySchedule)
        .where(DiscoverySchedule.organization_id == org_id)
        .order_by(DiscoverySchedule.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def create_schedule(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    agent_id: uuid.UUID,
    subnet: str,
    frequency: str,
) -> DiscoverySchedule:
    sched = DiscoverySchedule(
        organization_id=org_id,
        agent_id=agent_id,
        subnet=subnet.strip(),
        frequency=frequency,
        next_run_at=next_run(frequency),
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    return sched


async def get_schedule(db: AsyncSession, org_id: uuid.UUID, sched_id: uuid.UUID) -> DiscoverySchedule | None:
    return (
        await db.execute(
            select(DiscoverySchedule).where(
                DiscoverySchedule.id == sched_id, DiscoverySchedule.organization_id == org_id
            )
        )
    ).scalar_one_or_none()


async def delete_schedule(db: AsyncSession, sched: DiscoverySchedule) -> None:
    await db.delete(sched)
    await db.commit()


async def due_schedules(db: AsyncSession) -> list[DiscoverySchedule]:
    """Ratiba zote (org zote) zilizofikia wakati wake, kwa worker."""
    now = datetime.now(timezone.utc)
    stmt = select(DiscoverySchedule).where(
        DiscoverySchedule.enabled.is_(True), DiscoverySchedule.next_run_at <= now
    )
    return list((await db.execute(stmt)).scalars())


async def mark_ran(db: AsyncSession, sched: DiscoverySchedule) -> None:
    now = datetime.now(timezone.utc)
    sched.last_run_at = now
    sched.next_run_at = next_run(sched.frequency, frm=now)
    await db.commit()
