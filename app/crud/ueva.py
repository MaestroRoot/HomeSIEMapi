"""Shughuli za database kwa UEBA (baselines, anomalies, risk scores)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ueva import UserAnomaly, UserBaseline, UserRiskScore
from app.models.monitoring import Device


# --- Overview --------------------------------------------------------------


async def get_overview(db: AsyncSession, organization_id: uuid.UUID) -> dict:
    """Rudisha muhtasari wa UEBA kwa org."""
    # Jumla ya owner_names waliopo
    devices_stmt = (
        select(func.count(func.distinct(Device.owner_name)))
        .where(
            Device.organization_id == organization_id,
            Device.owner_name.isnot(None),
            Device.owner_name != "",
        )
    )
    total_users = (await db.execute(devices_stmt)).scalar() or 0

    # Baselines zilizokamilika
    baseline_stmt = (
        select(func.count(UserBaseline.id))
        .where(
            UserBaseline.organization_id == organization_id,
            UserBaseline.ready == True,  # noqa: E712
        )
    )
    baselines_ready = (await db.execute(baseline_stmt)).scalar() or 0

    baselines_pending = total_users - baselines_ready

    # Anomalies za leo
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    anomalies_today_stmt = (
        select(func.count(UserAnomaly.id))
        .where(
            UserAnomaly.organization_id == organization_id,
            UserAnomaly.created_at >= today,
        )
    )
    total_anomalies_today = (await db.execute(anomalies_today_stmt)).scalar() or 0

    # Critical/High users
    critical_stmt = (
        select(func.count(UserRiskScore.id))
        .where(
            UserRiskScore.organization_id == organization_id,
            UserRiskScore.current_score >= 70,
        )
    )
    critical_users = (await db.execute(critical_stmt)).scalar() or 0

    high_stmt = (
        select(func.count(UserRiskScore.id))
        .where(
            UserRiskScore.organization_id == organization_id,
            UserRiskScore.current_score >= 40,
            UserRiskScore.current_score < 70,
        )
    )
    high_users = (await db.execute(high_stmt)).scalar() or 0

    return {
        "total_users": total_users,
        "monitored_users": baselines_ready,
        "total_anomalies_today": total_anomalies_today,
        "critical_users": critical_users,
        "high_users": high_users,
        "baselines_ready": baselines_ready,
        "baselines_pending": baselines_pending,
    }


# --- Risk scores ----------------------------------------------------------


async def list_risk_scores(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[UserRiskScore]:
    """Rudisha risk scores zote za org, zimepangwa kwa score (juu zaidi kwanza)."""
    stmt = (
        select(UserRiskScore)
        .where(UserRiskScore.organization_id == organization_id)
        .order_by(UserRiskScore.current_score.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def get_risk_score(
    db: AsyncSession, organization_id: uuid.UUID, owner_name: str
) -> UserRiskScore | None:
    stmt = select(UserRiskScore).where(
        UserRiskScore.organization_id == organization_id,
        UserRiskScore.owner_name == owner_name,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def upsert_risk_score(
    db: AsyncSession,
    organization_id: uuid.UUID,
    owner_name: str,
    score: int,
    open_anomalies: int,
    total_anomalies: int,
) -> UserRiskScore:
    """Sasisha au unda risk score."""
    existing = await get_risk_score(db, organization_id, owner_name)
    now = datetime.now(timezone.utc)

    if existing:
        previous = existing.current_score
        existing.previous_score = previous
        existing.current_score = score
        existing.trend = "up" if score > previous else ("down" if score < previous else "stable")
        existing.open_anomalies = open_anomalies
        existing.total_anomalies = total_anomalies
        existing.last_updated_at = now
        await db.commit()
        await db.refresh(existing)
        return existing

    risk = UserRiskScore(
        organization_id=organization_id,
        owner_name=owner_name,
        current_score=score,
        previous_score=0,
        trend="stable",
        open_anomalies=open_anomalies,
        total_anomalies=total_anomalies,
        last_updated_at=now,
    )
    db.add(risk)
    await db.commit()
    await db.refresh(risk)
    return risk


# --- Anomalies ------------------------------------------------------------


async def list_anomalies(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    owner_name: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[UserAnomaly], int]:
    where = [UserAnomaly.organization_id == organization_id]
    if owner_name:
        where.append(UserAnomaly.owner_name == owner_name)
    if severity:
        where.append(UserAnomaly.severity == severity)
    if status:
        where.append(UserAnomaly.status == status)

    total = (await db.scalar(select(func.count(UserAnomaly.id)).where(*where))) or 0
    stmt = (
        select(UserAnomaly)
        .where(*where)
        .order_by(UserAnomaly.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list((await db.execute(stmt)).scalars())
    return rows, total


async def get_anomaly(
    db: AsyncSession, organization_id: uuid.UUID, anomaly_id: uuid.UUID
) -> UserAnomaly | None:
    stmt = select(UserAnomaly).where(
        UserAnomaly.id == anomaly_id,
        UserAnomaly.organization_id == organization_id,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_anomaly(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    owner_name: str,
    anomaly_type: str,
    severity: str,
    risk_score: int,
    description: str,
    evidence: dict,
    device_name: str | None = None,
) -> UserAnomaly:
    anomaly = UserAnomaly(
        organization_id=organization_id,
        owner_name=owner_name,
        anomaly_type=anomaly_type,
        severity=severity,
        risk_score=risk_score,
        description=description,
        evidence=evidence,
        device_name=device_name,
    )
    db.add(anomaly)
    await db.commit()
    await db.refresh(anomaly)
    return anomaly


async def update_anomaly_status(
    db: AsyncSession, anomaly: UserAnomaly, status: str
) -> UserAnomaly:
    anomaly.status = status
    await db.commit()
    await db.refresh(anomaly)
    return anomaly


# --- Baselines ------------------------------------------------------------


async def get_baseline(
    db: AsyncSession, organization_id: uuid.UUID, owner_name: str
) -> UserBaseline | None:
    stmt = select(UserBaseline).where(
        UserBaseline.organization_id == organization_id,
        UserBaseline.owner_name == owner_name,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def upsert_baseline(
    db: AsyncSession,
    organization_id: uuid.UUID,
    owner_name: str,
    *,
    normal_hours: dict,
    normal_processes: list,
    normal_domains: list,
    avg_daily_bytes: int,
    avg_daily_connections: int,
) -> UserBaseline:
    existing = await get_baseline(db, organization_id, owner_name)
    now = datetime.now(timezone.utc)

    if existing:
        existing.normal_hours = normal_hours
        existing.normal_processes = normal_processes
        existing.normal_domains = normal_domains
        existing.avg_daily_bytes = avg_daily_bytes
        existing.avg_daily_connections = avg_daily_connections
        existing.ready = True
        existing.last_refreshed_at = now
        await db.commit()
        await db.refresh(existing)
        return existing

    baseline = UserBaseline(
        organization_id=organization_id,
        owner_name=owner_name,
        normal_hours=normal_hours,
        normal_processes=normal_processes,
        normal_domains=normal_domains,
        avg_daily_bytes=avg_daily_bytes,
        avg_daily_connections=avg_daily_connections,
        ready=True,
        last_refreshed_at=now,
    )
    db.add(baseline)
    await db.commit()
    await db.refresh(baseline)
    return baseline


# --- User detail ----------------------------------------------------------


async def get_user_devices(
    db: AsyncSession, organization_id: uuid.UUID, owner_name: str
) -> list[str]:
    """Rudisha majina ya device zinazomilikiwa na mtumiaji."""
    stmt = select(Device.name).where(
        Device.organization_id == organization_id,
        Device.owner_name == owner_name,
    )
    return list((await db.execute(stmt)).scalars())
