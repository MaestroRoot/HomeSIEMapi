"""UEBA (User and Entity Behavior Analytics) endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.crud.ueva import (
    create_anomaly,
    get_anomaly,
    get_baseline,
    get_risk_score,
    get_user_devices,
    list_anomalies as crud_list_anomalies,
    list_risk_scores,
    get_overview,
    update_anomaly_status,
)
from app.core import ueba_engine
from app.schemas.ueva import (
    AnomalyList,
    AnomalyRead,
    AnomalyUpdate,
    UebaOverview,
    UserDetail,
    UserRiskList,
    UserRiskRead,
)

logger = get_logger(__name__)

router = APIRouter(tags=["ueba"])


# --- Overview --------------------------------------------------------------


@router.get("/ueba/overview", response_model=UebaOverview, summary="UEBA overview")
async def ueba_overview(user: CurrentUser, db: DbSession) -> UebaOverview:
    data = await get_overview(db, user.organization_id)
    return UebaOverview(**data)


# --- Risk scores -----------------------------------------------------------


@router.get("/ueba/users", response_model=UserRiskList, summary="List user risk scores")
async def list_user_risks(user: CurrentUser, db: DbSession) -> UserRiskList:
    rows = await list_risk_scores(db, user.organization_id)
    return UserRiskList(
        items=[UserRiskRead.model_validate(r) for r in rows],
        total=len(rows),
    )


@router.get("/ueba/users/{owner_name}", summary="Get user UEBA detail")
async def get_user_detail(
    owner_name: str, user: CurrentUser, db: DbSession
) -> UserDetail:
    risk = await get_risk_score(db, user.organization_id, owner_name)
    if risk is None:
        raise NotFoundError("No UEBA data for this user.", code="user_not_found")

    baseline = await get_baseline(db, user.organization_id, owner_name)
    anomalies, _ = await list_anomalies(
        db, user.organization_id, owner_name=owner_name, limit=20,
    )
    devices = await get_user_devices(db, user.organization_id, owner_name)

    # Build timeline from anomalies
    from app.schemas.ueva import UserTimelineEntry, UserBaselineRead, UserRiskRead

    timeline = [
        UserTimelineEntry(
            time=a.created_at,
            activity_type=a.anomaly_type,
            description=a.description,
            severity=a.severity,
            source="ueba_engine",
            details=a.evidence,
        )
        for a in anomalies
    ]

    baseline_read = None
    if baseline:
        baseline_read = UserBaselineRead(
            owner_name=baseline.owner_name,
            normal_hours=baseline.normal_hours,
            normal_processes=baseline.normal_processes,
            normal_domains=baseline.normal_domains,
            avg_daily_bytes=baseline.avg_daily_bytes,
            avg_daily_connections=baseline.avg_daily_connections,
            ready=baseline.ready,
            last_refreshed_at=baseline.last_refreshed_at,
        )

    return UserDetail(
        owner_name=owner_name,
        risk_score=UserRiskRead.model_validate(risk),
        baseline=baseline_read,
        recent_anomalies=[AnomalyRead.model_validate(a) for a in anomalies],
        timeline=timeline,
        devices=devices,
    )


# --- Anomalies ------------------------------------------------------------


@router.get("/ueba/anomalies", response_model=AnomalyList, summary="List anomalies")
async def list_anomalies(
    user: CurrentUser,
    db: DbSession,
    owner_name: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    status: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AnomalyList:
    rows, total = await crud_list_anomalies(
        db,
        user.organization_id,
        owner_name=owner_name,
        severity=severity,
        status=status,
        limit=limit,
    )
    return AnomalyList(
        items=[AnomalyRead.model_validate(r) for r in rows],
        total=total,
    )


@router.patch(
    "/ueba/anomalies/{anomaly_id}",
    response_model=AnomalyRead,
    summary="Update anomaly status",
)
async def update_anomaly(
    anomaly_id: uuid.UUID,
    payload: AnomalyUpdate,
    user: RequireAnalyst,
    db: DbSession,
) -> AnomalyRead:
    anomaly = await get_anomaly(db, user.organization_id, anomaly_id)
    if anomaly is None:
        raise NotFoundError("Anomaly not found.", code="anomaly_not_found")
    anomaly = await update_anomaly_status(db, anomaly, payload.status)
    logger.info("Anomaly %s status updated to %s", anomaly_id, payload.status)
    return AnomalyRead.model_validate(anomaly)


# --- Engine actions --------------------------------------------------------


@router.post("/ueba/analyze/{owner_name}", summary="Run UEBA analysis for a user")
async def analyze_user(
    owner_name: str, user: RequireAnalyst, db: DbSession
) -> dict:
    """Chunguza tabia ya mtumiaji na ugundue anomalies."""
    anomalies = await ueba_engine.analyze_owner(
        db, user.organization_id, owner_name,
    )
    return {
        "owner_name": owner_name,
        "anomalies_found": len(anomalies),
        "anomalies": [
            {
                "type": a.anomaly_type,
                "severity": a.severity,
                "score": a.risk_score,
                "description": a.description,
            }
            for a in anomalies
        ],
    }


@router.post("/ueba/baseline/{owner_name}", summary="Build baseline for a user")
async def build_baseline(
    owner_name: str, user: RequireAnalyst, db: DbSession
) -> dict:
    """Jenga baseline kutoka data ya historia."""
    await ueba_engine.build_baseline(db, user.organization_id, owner_name)
    return {"detail": f"Baseline built for {owner_name}."}
