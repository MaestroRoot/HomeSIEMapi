"""Read endpoints kwa logs, vulnerabilities, forensics (upande wa dashboard)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import distinct, func, select

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.models.monitoring import ForensicSnapshot, LogEntry, Vulnerability
from app.schemas.common import CamelModel
from app.schemas.telemetry import ForensicRead, LogRead, VulnRead, VulnStatusUpdate

router = APIRouter(tags=["telemetry"])


class LogList(CamelModel):
    items: list[LogRead]
    sources: list[str]
    total: int


@router.get("/logs", response_model=LogList, summary="Recent log entries")
async def list_logs(
    user: CurrentUser,
    db: DbSession,
    source: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> LogList:
    org = LogEntry.organization_id == user.organization_id
    where = [org]
    if source:
        where.append(LogEntry.source == source)

    total = int(await db.scalar(select(func.count(LogEntry.id)).where(*where)) or 0)
    rows = list(
        (
            await db.execute(
                select(LogEntry).where(*where).order_by(LogEntry.created_at.desc()).limit(limit)
            )
        ).scalars()
    )
    sources = [
        s
        for s in (
            await db.execute(select(distinct(LogEntry.source)).where(org))
        ).scalars()
    ]
    return LogList(items=[LogRead.model_validate(r) for r in rows], sources=sources, total=total)


@router.get("/vulnerabilities", response_model=list[VulnRead], summary="Discovered vulnerabilities")
async def list_vulnerabilities(user: CurrentUser, db: DbSession) -> list[VulnRead]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = list(
        (
            await db.execute(
                select(Vulnerability)
                .where(Vulnerability.organization_id == user.organization_id)
                .order_by(Vulnerability.created_at.desc())
            )
        ).scalars()
    )
    rows.sort(key=lambda v: order.get(v.severity, 9))
    return [VulnRead.model_validate(r) for r in rows]


@router.patch("/vulnerabilities/{vuln_id}", response_model=VulnRead, summary="Update remediation status")
async def update_vulnerability(
    vuln_id: uuid.UUID, payload: VulnStatusUpdate, user: RequireAnalyst, db: DbSession
) -> VulnRead:
    row = (
        await db.execute(
            select(Vulnerability).where(
                Vulnerability.id == vuln_id, Vulnerability.organization_id == user.organization_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError("No such finding.", code="vuln_not_found")
    row.status = payload.status
    await db.commit()
    await db.refresh(row)
    return VulnRead.model_validate(row)


@router.get("/forensics", response_model=list[ForensicRead], summary="Forensic snapshots")
async def list_forensics(user: CurrentUser, db: DbSession) -> list[ForensicRead]:
    rows = list(
        (
            await db.execute(
                select(ForensicSnapshot)
                .where(ForensicSnapshot.organization_id == user.organization_id)
                .order_by(ForensicSnapshot.created_at.desc())
                .limit(20)
            )
        ).scalars()
    )
    return [ForensicRead.model_validate(r) for r in rows]
