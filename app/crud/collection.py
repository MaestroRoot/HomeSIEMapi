"""CRUD ya collection streams (ukusanyaji unaoendelea wa capture/logs)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import CollectionStream


async def upsert_stream(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    agent_id: uuid.UUID,
    kind: str,
    params: dict,
) -> CollectionStream:
    """Anzisha (au sasisha + wezesha) stream ya (agent, kind). Moja tu kwa kila jozi."""
    existing = (
        await db.execute(
            select(CollectionStream).where(
                CollectionStream.organization_id == organization_id,
                CollectionStream.agent_id == agent_id,
                CollectionStream.kind == kind,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.params = params
        existing.enabled = True
        await db.commit()
        await db.refresh(existing)
        return existing

    stream = CollectionStream(
        organization_id=organization_id, agent_id=agent_id, kind=kind, params=params, enabled=True
    )
    db.add(stream)
    await db.commit()
    await db.refresh(stream)
    return stream


async def list_streams(db: AsyncSession, organization_id: uuid.UUID) -> list[CollectionStream]:
    stmt = (
        select(CollectionStream)
        .where(CollectionStream.organization_id == organization_id)
        .order_by(CollectionStream.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def get_stream(
    db: AsyncSession, organization_id: uuid.UUID, stream_id: uuid.UUID
) -> CollectionStream | None:
    return (
        await db.execute(
            select(CollectionStream).where(
                CollectionStream.id == stream_id, CollectionStream.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()


async def delete_stream(db: AsyncSession, stream: CollectionStream) -> None:
    await db.delete(stream)
    await db.commit()


async def enabled_streams_for_agent(
    db: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID
) -> list[CollectionStream]:
    stmt = select(CollectionStream).where(
        CollectionStream.organization_id == organization_id,
        CollectionStream.agent_id == agent_id,
        CollectionStream.enabled.is_(True),
    )
    return list((await db.execute(stmt)).scalars())
