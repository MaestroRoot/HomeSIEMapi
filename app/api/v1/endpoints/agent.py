"""Agent command-and-control.

Upande wa host (agent, auth ya X-Sensor-Token):
  POST /agent/enroll            -> jisajili, pata agentId
  GET  /agent/{id}/jobs         -> chukua pending jobs (zinawekwa 'running')
  POST /agent/jobs/{jobId}/result -> rudisha matokeo

Upande wa dashboard (auth ya user):
  GET  /agents                  -> orodha ya agents
  POST /agents/{id}/jobs        -> tengeneza job (scan/forensics/...)
  GET  /agents/jobs             -> jobs za hivi karibuni (status)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import Field, field_serializer
from sqlalchemy import delete

from app.api.deps import CurrentUser, DbSession, RequireAnalyst, SensorOrg
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.crud import agent as crud
from app.crud import collection as stream_crud
from app.crud import inventory as inv_crud
from app.crud import monitoring as mon_crud
from app.models.monitoring import ForensicSnapshot, Vulnerability
from app.schemas.agent import (
    AgentRead,
    EnrollRequest,
    EnrollResponse,
    JobCreate,
    JobForAgent,
    JobRead,
    JobResult,
)
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(tags=["agent"])


# --- agent-facing ---------------------------------------------------------


@router.post("/agent/enroll", response_model=EnrollResponse, summary="Enroll an agent (first run)")
async def enroll(payload: EnrollRequest, org_id: SensorOrg, db: DbSession) -> EnrollResponse:
    agent = await crud.enroll(
        db,
        org_id,
        hostname=payload.hostname,
        os=payload.os,
        ip=payload.ip,
        capabilities=payload.capabilities,
    )
    return EnrollResponse(agent_id=agent.id)


@router.get("/agent/{agent_id}/jobs", response_model=list[JobForAgent], summary="Poll pending jobs")
async def poll_jobs(agent_id: uuid.UUID, org_id: SensorOrg, db: DbSession) -> list[JobForAgent]:
    agent = await crud.get_agent(db, org_id, agent_id)
    if agent is None:
        raise NotFoundError(
            "This agent is no longer enrolled. Re-enroll with a valid token.",
            code="agent_not_found",
        )
    await crud.touch_agent(db, agent_id)
    # Streams zinazoendelea (capture/logs): tengeneza job mpya endapo hakuna
    # inayoendelea. Hii ndiyo inayofanya "Auto" iendelee hata dashboard imefungwa.
    for stream in await stream_crud.enabled_streams_for_agent(db, org_id, agent_id):
        if not await crud.has_active_job(db, org_id, agent_id, stream.kind):
            await crud.create_job(db, org_id, agent_id, kind=stream.kind, params=dict(stream.params or {}))
    jobs = await crud.pending_jobs_for_agent(db, org_id, agent_id)
    return [JobForAgent(id=j.id, kind=j.kind, params=j.params) for j in jobs]


@router.post("/agent/jobs/{job_id}/result", summary="Submit job result")
async def submit_result(job_id: uuid.UUID, payload: JobResult, org_id: SensorOrg, db: DbSession) -> dict:
    job = await crud.get_job(db, org_id, job_id)
    if job is None:
        raise NotFoundError("No such job.", code="job_not_found")

    result = payload.result or {}

    # Hifadhi matokeo kwenye table husika kulingana na aina ya job.
    if payload.status == "done" and job.kind == "scan":
        target = result.get("target", "")
        await db.execute(
            delete(Vulnerability).where(
                Vulnerability.organization_id == org_id, Vulnerability.target == target
            )
        )
        for f in result.get("findings", []):
            db.add(
                Vulnerability(
                    organization_id=org_id,
                    target=target,
                    port=f.get("port"),
                    service=f.get("service"),
                    severity=f.get("severity", "info"),
                    title=(f.get("title") or "")[:200],
                    detail=f.get("detail", ""),
                    fix=f.get("fix", ""),
                )
            )
    elif payload.status == "done" and job.kind == "forensics":
        db.add(
            ForensicSnapshot(
                organization_id=org_id,
                host=result.get("host", "host"),
                processes=result.get("processes", []),
                connections=result.get("connections", []),
            )
        )
    elif payload.status == "done" and job.kind == "discovery":
        for h in result.get("hosts", []):
            await mon_crud.upsert_discovered_device(
                db, org_id, mac=h.get("mac"), ip=h.get("ip"), hostname=h.get("hostname")
            )
    elif payload.status == "done" and job.kind == "software":
        agent = await crud.get_agent(db, org_id, job.agent_id)
        await inv_crud.replace_for_host(
            db,
            org_id,
            host=result.get("host", "host"),
            device_id=agent.device_id if agent is not None else None,
            packages=result.get("software", []),
        )

    await crud.finish_job(db, job, status=payload.status, result=result, error=payload.error)
    logger.info("Agent job %s (%s) -> %s", job_id, job.kind, payload.status)
    return {"detail": "ok"}


# --- dashboard-facing -----------------------------------------------------


@router.get("/agents", response_model=list[AgentRead], summary="List enrolled agents")
async def list_agents(user: CurrentUser, db: DbSession) -> list[AgentRead]:
    rows = await crud.list_agents(db, user.organization_id)
    return [AgentRead.model_validate(a) for a in rows]


@router.post("/agents/{agent_id}/jobs", response_model=JobRead, summary="Queue a job for an agent")
async def create_job(
    agent_id: uuid.UUID, payload: JobCreate, user: CurrentUser, db: DbSession
) -> JobRead:
    agent = await crud.get_agent(db, user.organization_id, agent_id)
    if agent is None:
        raise NotFoundError("No such agent.", code="agent_not_found")
    job = await crud.create_job(db, user.organization_id, agent_id, kind=payload.kind, params=payload.params)
    return JobRead.model_validate(job)


@router.delete("/agents/{agent_id}", response_model=Message, summary="Delete an agent")
async def delete_agent(agent_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    agent = await crud.get_agent(db, user.organization_id, agent_id)
    if agent is None:
        raise NotFoundError("No such agent.", code="agent_not_found")
    await crud.delete_agent(db, agent)
    logger.info("Agent %s imefutwa na %s", agent_id, user.email)
    return Message(detail="Agent removed.", code="agent_deleted")


@router.get("/agents/jobs", response_model=list[JobRead], summary="Recent jobs")
async def list_jobs(
    user: CurrentUser,
    db: DbSession,
    agent_id: Annotated[uuid.UUID | None, Query(alias="agentId")] = None,
) -> list[JobRead]:
    rows = await crud.recent_jobs(db, user.organization_id, agent_id=agent_id)
    return [JobRead.model_validate(j) for j in rows]


# --- continuous collection streams ----------------------------------------

StreamKind = Literal["capture", "logs"]


class StreamRead(CamelModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    kind: StreamKind
    params: dict
    enabled: bool
    created_at: datetime

    @field_serializer("id", "agent_id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


class StreamCreate(CamelModel):
    agent_id: uuid.UUID
    kind: StreamKind
    params: dict = Field(default_factory=dict)


@router.get("/collection/streams", response_model=list[StreamRead], summary="List continuous collection streams")
async def list_streams(user: CurrentUser, db: DbSession) -> list[StreamRead]:
    rows = await stream_crud.list_streams(db, user.organization_id)
    return [StreamRead.model_validate(s) for s in rows]


@router.post("/collection/streams", response_model=StreamRead, summary="Start continuous collection (keeps running until stopped)")
async def start_stream(payload: StreamCreate, user: RequireAnalyst, db: DbSession) -> StreamRead:
    agent = await crud.get_agent(db, user.organization_id, payload.agent_id)
    if agent is None:
        raise NotFoundError("No such agent.", code="agent_not_found")
    stream = await stream_crud.upsert_stream(
        db, user.organization_id, agent_id=payload.agent_id, kind=payload.kind, params=payload.params
    )
    return StreamRead.model_validate(stream)


@router.delete("/collection/streams/{stream_id}", response_model=Message, summary="Stop a collection stream")
async def stop_stream(stream_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    stream = await stream_crud.get_stream(db, user.organization_id, stream_id)
    if stream is None:
        raise NotFoundError("No such stream.", code="stream_not_found")
    await stream_crud.delete_stream(db, stream)
    return Message(detail="Collection stopped.", code="stream_stopped")
