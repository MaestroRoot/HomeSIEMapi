"""CRUD ya Cloudflare Gateway config (per-org)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import CloudflareGatewayConfig


async def get_for_org(db: AsyncSession, org_id: uuid.UUID) -> CloudflareGatewayConfig | None:
    return (
        await db.execute(select(CloudflareGatewayConfig).where(CloudflareGatewayConfig.organization_id == org_id))
    ).scalar_one_or_none()


async def upsert(
    db: AsyncSession, org_id: uuid.UUID, *, account_id: str, api_token: str
) -> CloudflareGatewayConfig:
    cfg = await get_for_org(db, org_id)
    if cfg is not None:
        cfg.account_id = account_id.strip()
        cfg.api_token = api_token.strip()
        cfg.enabled = True
        cfg.last_status = None
    else:
        cfg = CloudflareGatewayConfig(
            organization_id=org_id,
            account_id=account_id.strip(),
            api_token=api_token.strip(),
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


async def all_enabled(db: AsyncSession) -> list[CloudflareGatewayConfig]:
    """Config zote zilizowashwa (org zote), kwa poller."""
    stmt = select(CloudflareGatewayConfig).where(CloudflareGatewayConfig.enabled.is_(True))
    return list((await db.execute(stmt)).scalars())


async def mark_synced(
    db: AsyncSession,
    cfg: CloudflareGatewayConfig,
    *,
    status: str,
    last_event_at: datetime | None = None,
    location_id: str | None = None,
    location_name: str | None = None,
) -> None:
    from datetime import timezone

    cfg.last_synced_at = datetime.now(timezone.utc)
    cfg.last_status = status[:200]
    if last_event_at is not None:
        cfg.last_event_at = last_event_at
    if location_id is not None:
        cfg.location_id = location_id
    if location_name is not None:
        cfg.location_name = location_name
    await db.commit()