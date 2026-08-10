"""CRUD ya data sources (registry + health read-time)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import SecurityEvent
from app.models.siem import DataSource

#: Ikiwa chanzo hakijatuma tukio kwa muda gani, kinahesabiwa:
_HEALTHY_MAX_SECONDS = 300          # 5 min -> healthy
_DEGRADED_MAX_SECONDS = 3600        # 1 hr  -> degraded
#: Zaidi ya hapo -> offline (bado kinajulikana) au inactive (hakijawahi tuma).


async def ensure_source(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    name: str,
    type: str,
) -> DataSource:
    """Pata au unde chanzo kwa (org, name). Inasasisha `last_event_at` kwa
    sasa. Inatumiwa na ingest pipeline kujisajili kiotomatiki."""
    name = (name or "sensor").strip()[:120] or "sensor"
    stmt = select(DataSource).where(
        DataSource.organization_id == organization_id, DataSource.name == name
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = DataSource(
            organization_id=organization_id,
            name=name,
            type=(type or "sensor").strip()[:24] or "sensor",
        )
        db.add(row)
        await db.flush()
    else:
        row.type = (type or row.type or "sensor").strip()[:24] or "sensor"
    row.last_event_at = datetime.now(timezone.utc)
    row.events_total = (row.events_total or 0) + 1
    return row


async def mark_source_error(db: AsyncSession, row: DataSource, error: str) -> None:
    row.last_error = error[:400]
    row.last_event_at = datetime.now(timezone.utc)
    await db.flush()


async def list_sources(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[tuple[DataSource, dict]]:
    """Rudisha (source, stats) kwa ajili ya health page. Stats zinahesabiwa
    read-time kutoka security_events (kwa `source` column)."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    hour_ago = now - timedelta(hours=1)

    # Jumla ya matukio kwa chanzo, ndani ya dirisha.
    per_source_24h = dict(
        (
            await db.execute(
                select(SecurityEvent.source, func.count(SecurityEvent.id))
                .where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.occurred_at.isnot(None),
                    SecurityEvent.occurred_at >= day_ago,
                )
                .group_by(SecurityEvent.source)
            )
        ).all()
    )
    per_source_1h = dict(
        (
            await db.execute(
                select(SecurityEvent.source, func.count(SecurityEvent.id))
                .where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.occurred_at.isnot(None),
                    SecurityEvent.occurred_at >= hour_ago,
                )
                .group_by(SecurityEvent.source)
            )
        ).all()
    )

    stmt = (
        select(DataSource)
        .where(DataSource.organization_id == organization_id)
        .order_by(DataSource.last_event_at.desc().nulls_last(), DataSource.name.asc())
    )
    rows = list((await db.execute(stmt)).scalars())
    out: list[tuple[DataSource, dict]] = []
    for row in rows:
        # events kutoka security_events zinaweza kuwa na source tofauti (majina ya
        # zamani) — tunaangalia source name ya chanzo + jina lake.
        c24 = per_source_24h.get(row.name, 0)
        c1h = per_source_1h.get(row.name, 0)
        out.append(
            (
                row,
                {
                    "events_24h": int(c24 or 0),
                    "events_1h": int(c1h or 0),
                    "eps": round(float(c1h or 0) / 3600.0, 2),
                },
            )
        )
    return out


def source_status(row: DataSource) -> str:
    if not row.enabled:
        return "offline"
    if row.last_event_at is None:
        return "inactive"
    age = (datetime.now(timezone.utc) - row.last_event_at).total_seconds()
    if age <= _HEALTHY_MAX_SECONDS:
        return "healthy"
    if age <= _DEGRADED_MAX_SECONDS:
        return "degraded"
    return "offline"


async def register_source(
    db: AsyncSession, organization_id: uuid.UUID, *, name: str, type: str, enabled: bool
) -> DataSource:
    row = await ensure_source(db, organization_id, name=name, type=type)
    row.enabled = enabled
    await db.commit()
    await db.refresh(row)
    return row


async def get_source(
    db: AsyncSession, organization_id: uuid.UUID, source_id: uuid.UUID
) -> DataSource | None:
    stmt = select(DataSource).where(
        DataSource.id == source_id, DataSource.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def update_source(
    db: AsyncSession, row: DataSource, *, name: str | None, type: str | None, enabled: bool | None
) -> DataSource:
    if name is not None:
        row.name = name.strip()[:120]
    if type is not None:
        row.type = type.strip()[:24]
    if enabled is not None:
        row.enabled = enabled
    await db.commit()
    await db.refresh(row)
    return row
