"""CRUD ya notification channels."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import NotificationChannel


async def list_channels(db: AsyncSession, organization_id: uuid.UUID) -> list[NotificationChannel]:
    stmt = (
        select(NotificationChannel)
        .where(NotificationChannel.organization_id == organization_id)
        .order_by(NotificationChannel.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def enabled_channels(db: AsyncSession, organization_id: uuid.UUID) -> list[NotificationChannel]:
    stmt = select(NotificationChannel).where(
        NotificationChannel.organization_id == organization_id, NotificationChannel.enabled.is_(True)
    )
    return list((await db.execute(stmt)).scalars())


async def create_channel(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    type: str,
    name: str,
    target: str,
    min_severity: str,
) -> NotificationChannel:
    ch = NotificationChannel(
        organization_id=organization_id,
        type=type,
        name=name.strip(),
        target=target.strip(),
        min_severity=min_severity,
    )
    db.add(ch)
    await db.commit()
    await db.refresh(ch)
    return ch


async def get_channel(
    db: AsyncSession, organization_id: uuid.UUID, channel_id: uuid.UUID
) -> NotificationChannel | None:
    return (
        await db.execute(
            select(NotificationChannel).where(
                NotificationChannel.id == channel_id,
                NotificationChannel.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()


async def delete_channel(db: AsyncSession, ch: NotificationChannel) -> None:
    await db.delete(ch)
    await db.commit()


async def mark_sent(db: AsyncSession, channels: list[NotificationChannel]) -> None:
    now = datetime.now(timezone.utc)
    for ch in channels:
        ch.last_sent_at = now
    if channels:
        await db.commit()
