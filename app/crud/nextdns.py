"""CRUD ya NextDNS config (per-org).

Reseller model: single NextDNS API key from settings, profile per org.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import NextDnsConfig


async def get_for_org(db: AsyncSession, org_id: uuid.UUID) -> NextDnsConfig | None:
    return (
        await db.execute(select(NextDnsConfig).where(NextDnsConfig.organization_id == org_id))
    ).scalar_one_or_none()


async def upsert(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    profile_id: str | None = None,
    profile_name: str | None = None,
) -> NextDnsConfig:
    """Create config for org (no credentials needed - uses global settings)."""
    cfg = await get_for_org(db, org_id)
    if cfg is not None:
        cfg.enabled = True
        cfg.last_status = None
        if profile_id is not None:
            cfg.profile_id = profile_id
        if profile_name is not None:
            cfg.profile_name = profile_name
    else:
        cfg = NextDnsConfig(
            organization_id=org_id,
            profile_id=profile_id,
            profile_name=profile_name,
            enabled=True,
        )
        db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return cfg


async def delete_for_org(db: AsyncSession, org_id: uuid.UUID) -> NextDnsConfig | None:
    cfg = await get_for_org(db, org_id)
    if cfg is None:
        return None
    await db.delete(cfg)
    await db.commit()
    return cfg


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
    cfg.last_synced_at = datetime.now(timezone.utc)
    cfg.last_status = status[:200]
    if last_event_at is not None:
        cfg.last_event_at = last_event_at
    await db.commit()
