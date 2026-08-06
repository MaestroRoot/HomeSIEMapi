"""CRUD ya NextDNS config (per-org)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import NextDnsConfig


async def get_for_org(db: AsyncSession, org_id: uuid.UUID) -> NextDnsConfig | None:
    return (
        await db.execute(select(NextDnsConfig).where(NextDnsConfig.organization_id == org_id))
    ).scalar_one_or_none()


async def upsert(
    db: AsyncSession, org_id: uuid.UUID, *, profile_id: str, api_key: str
) -> NextDnsConfig:
    cfg = await get_for_org(db, org_id)
    if cfg is not None:
        cfg.profile_id = profile_id.strip()
        cfg.api_key = api_key.strip()
        cfg.enabled = True
        cfg.last_status = None
    else:
        cfg = NextDnsConfig(
            organization_id=org_id,
            profile_id=profile_id.strip(),
            api_key=api_key.strip(),
            enabled=True,
        )
        db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return cfg


async def delete_for_org(db: AsyncSession, org_id: uuid.UUID) -> bool:
    cfg = await get_for_org(db, org_id)
    if cfg is None:
        return False
    await db.delete(cfg)
    await db.commit()
    return True


async def all_enabled(db: AsyncSession) -> list[NextDnsConfig]:
    """Config zote zilizowashwa (org zote), kwa poller."""
    stmt = select(NextDnsConfig).where(NextDnsConfig.enabled.is_(True))
    return list((await db.execute(stmt)).scalars())


async def mark_synced(
    db: AsyncSession,
    cfg: NextDnsConfig,
    *,
    status: str,
    last_event_at: datetime | None = None,
) -> None:
    from datetime import timezone

    cfg.last_synced_at = datetime.now(timezone.utc)
    cfg.last_status = status[:200]
    if last_event_at is not None:
        cfg.last_event_at = last_event_at
    await db.commit()
