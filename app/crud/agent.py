"""CRUD ya agents na agent jobs."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crud import monitoring as mon_crud
from app.models.monitoring import Agent, AgentJob


async def enroll(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    hostname: str,
    os: str | None,
    ip: str | None,
    capabilities: list[str],
) -> Agent:
    """Sajili agent (au sasisha ikiwa host ile ile imesharejea)."""
    existing = (
        await db.execute(
            select(Agent).where(Agent.organization_id == organization_id, Agent.hostname == hostname)
        )
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    # Jaribu kuoanisha na Device kwa IP (kama inajulikana).
    device = await mon_crud.match_or_create_device(db, organization_id, mac=None, ip=ip) if ip else None

    if existing is not None:
        existing.os = os or existing.os
        existing.last_ip = ip or existing.last_ip
        existing.capabilities = capabilities or existing.capabilities
        existing.last_seen_at = now
        if device is not None:
            existing.device_id = device.id
        await db.commit()
        await db.refresh(existing)
        return existing

    agent = Agent(
        organization_id=organization_id,
        hostname=hostname,
        os=os,
        last_ip=ip,
        capabilities=capabilities,
        last_seen_at=now,
        device_id=device.id if device is not None else None,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent


async def list_agents(db: AsyncSession, organization_id: uuid.UUID) -> list[Agent]:
    stmt = select(Agent).where(Agent.organization_id == organization_id).order_by(Agent.hostname)
    return list((await db.execute(stmt)).scalars())


async def get_agent(db: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID) -> Agent | None:
    return (
        await db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.organization_id == organization_id)
        )
    ).scalar_one_or_none()


async def delete_agent(db: AsyncSession, agent: Agent) -> None:
    """Futa agent. Jobs/streams/discovery-schedules zake zina-cascade (FK)."""
    await db.delete(agent)
    await db.commit()


async def touch_agent(db: AsyncSession, agent_id: uuid.UUID) -> None:
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if agent is not None:
        agent.last_seen_at = datetime.now(timezone.utc)
        await db.commit()


# --- jobs -----------------------------------------------------------------


async def create_job(
    db: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID, *, kind: str, params: dict
) -> AgentJob:
    job = AgentJob(
        organization_id=organization_id, agent_id=agent_id, kind=kind, params=params, status="pending"
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


async def has_active_job(
    db: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID, kind: str
) -> bool:
    """Je, agent ina job ya aina hii bado (pending au running)?"""
    stmt = select(AgentJob.id).where(
        AgentJob.organization_id == organization_id,
        AgentJob.agent_id == agent_id,
        AgentJob.kind == kind,
        AgentJob.status.in_(("pending", "running")),
    ).limit(1)
    return (await db.execute(stmt)).first() is not None


async def pending_jobs_for_agent(
    db: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID
) -> list[AgentJob]:
    """Rudisha pending jobs, ukiziweka 'running' ili zisirudiwe."""
    stmt = (
        select(AgentJob)
        .where(
            AgentJob.organization_id == organization_id,
            AgentJob.agent_id == agent_id,
            AgentJob.status == "pending",
        )
        .order_by(AgentJob.created_at)
    )
    jobs = list((await db.execute(stmt)).scalars())
    for j in jobs:
        j.status = "running"
    if jobs:
        await db.commit()
    return jobs


async def get_job(db: AsyncSession, organization_id: uuid.UUID, job_id: uuid.UUID) -> AgentJob | None:
    return (
        await db.execute(
            select(AgentJob).where(AgentJob.id == job_id, AgentJob.organization_id == organization_id)
        )
    ).scalar_one_or_none()


async def finish_job(
    db: AsyncSession, job: AgentJob, *, status: str, result: dict | None, error: str | None
) -> AgentJob:
    job.status = status
    job.result = result
    job.error = error
    await db.commit()
    await db.refresh(job)
    return job


async def recent_jobs(
    db: AsyncSession, organization_id: uuid.UUID, *, agent_id: uuid.UUID | None = None, limit: int = 50
) -> list[AgentJob]:
    where = [AgentJob.organization_id == organization_id]
    if agent_id:
        where.append(AgentJob.agent_id == agent_id)
    stmt = select(AgentJob).where(*where).order_by(AgentJob.created_at.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars())
