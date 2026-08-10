"""CRUD ya alerts: fingerprinting, lifecycle (ack/assign/snooze/resolve), SLA."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import DetectionRule, SecurityEvent
from app.models.siem import Alert

#: SLA (dakika) kwa kila severity.
_SLA_MINUTES = {"info": 180, "low": 120, "medium": 60, "high": 30, "critical": 15}

_OPEN = ("new", "acknowledged", "assigned", "snoozed")


def fingerprint(rule: DetectionRule, indicator: str) -> str:
    """Kiashiria cha kipekee: rule + kikundi + indicator."""
    return f"{rule.id}:{rule.group_by or '-'}:{indicator}"


def sla_due_at(severity: str) -> datetime:
    minutes = _SLA_MINUTES.get(severity, 60)
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


async def open_existing(
    db: AsyncSession, organization_id: uuid.UUID, fp: str
) -> Alert | None:
    """Alert yenye fingerprint hiyo inayobaki wazi (isiyo resolved)."""
    stmt = select(Alert).where(
        Alert.organization_id == organization_id,
        Alert.fingerprint == fp,
        Alert.status.in_(_OPEN),
    )
    return (await db.execute(stmt)).scalars().first()


async def create_alert(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    rule: DetectionRule,
    event: SecurityEvent,
) -> Alert:
    """Unda alert mpya (au usongeze ya zamani) kwa fingerprint ya rule+indicator."""
    indicator = event_indicator(event)
    fp = fingerprint(rule, indicator)
    existing = await open_existing(db, organization_id, fp)
    if existing is not None:
        existing.event_count = (existing.event_count or 0) + 1
        existing.last_seen_at = event.occurred_at or datetime.now(timezone.utc)
        if existing.sla_due_at is None:
            existing.sla_due_at = sla_due_at(existing.severity)
        if len(existing.event_ids or []) < 500:
            ids = list(existing.event_ids or [])
            ids.append(str(event.id))
            existing.event_ids = ids
        return existing

    alert = Alert(
        organization_id=organization_id,
        rule_id=rule.id,
        title=rule.name,
        description=rule.description or "",
        severity=rule.severity,
        status="new",
        fingerprint=fp,
        event_count=1,
        first_seen_at=event.occurred_at or datetime.now(timezone.utc),
        last_seen_at=event.occurred_at or datetime.now(timezone.utc),
        sla_due_at=sla_due_at(rule.severity),
        event_ids=[str(event.id)],
        entities=_entities_for(event),
    )
    db.add(alert)
    await db.flush()
    return alert


def event_indicator(event: SecurityEvent) -> str:
    if event.domain:
        return event.domain
    if event.dst_ip:
        return event.dst_ip
    if event.src_ip:
        return event.src_ip
    if event.account:
        return event.account
    if event.process_name:
        return event.process_name
    return "?"


def _entities_for(event: SecurityEvent) -> list[dict]:
    """Entities (devices/IPs/domains/accounts) zinazohusika na event."""
    out: list[dict] = []
    if event.device_id:
        out.append({"type": "device", "value": str(event.device_id)})
    if event.domain:
        out.append({"type": "domain", "value": event.domain})
    ip = event.src_ip or event.dst_ip
    if ip:
        out.append({"type": "ip", "value": ip})
    if event.account:
        out.append({"type": "account", "value": event.account})
    if event.process_name:
        out.append({"type": "process", "value": event.process_name})
    return out


async def list_alerts(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Alert], int]:
    stmt = select(Alert).where(Alert.organization_id == organization_id)
    count_stmt = select(func.count(Alert.id)).where(Alert.organization_id == organization_id)
    if status:
        stmt = stmt.where(Alert.status == status)
        count_stmt = count_stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
        count_stmt = count_stmt.where(Alert.severity == severity)
    stmt = stmt.order_by(Alert.last_seen_at.desc().nulls_last()).limit(limit).offset(offset)
    total = int(await db.scalar(count_stmt) or 0)
    rows = list((await db.execute(stmt)).scalars())
    return rows, total


async def get_alert(
    db: AsyncSession, organization_id: uuid.UUID, alert_id: uuid.UUID
) -> Alert | None:
    stmt = select(Alert).where(
        Alert.id == alert_id, Alert.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def set_status(
    db: AsyncSession,
    alert: Alert,
    status: str,
    *,
    assignee: str | None = None,
    snooze_minutes: int | None = None,
    false_positive: bool | None = None,
    note: str | None = None,
) -> Alert:
    alert.status = status
    if status == "resolved":
        alert.resolved_at = datetime.now(timezone.utc)
        alert.sla_due_at = None
    elif status in ("acknowledged", "assigned"):
        if alert.resolved_at:
            alert.resolved_at = None
    if assignee is not None:
        alert.assignee = assignee
    if snooze_minutes is not None and status == "snoozed":
        alert.snoozed_until = datetime.now(timezone.utc) + timedelta(minutes=snooze_minutes)
    if false_positive is not None:
        alert.is_false_positive = false_positive
    if note is not None:
        alert.resolution_note = note[:1000]
    await db.commit()
    await db.refresh(alert)
    return alert


async def alert_counts(db: AsyncSession, organization_id: uuid.UUID) -> dict:
    now = datetime.now(timezone.utc)
    counts = dict(
        (
            await db.execute(
                select(Alert.status, func.count(Alert.id))
                .where(Alert.organization_id == organization_id)
                .group_by(Alert.status)
            )
        ).all()
    )
    overdue = int(
        await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.organization_id == organization_id,
                Alert.status.in_(_OPEN),
                Alert.sla_due_at.isnot(None),
                Alert.sla_due_at < now,
            )
        )
        or 0
    )
    resolved_24h = int(
        await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.organization_id == organization_id,
                Alert.status == "resolved",
                Alert.resolved_at.isnot(None),
                Alert.resolved_at >= now - timedelta(hours=24),
            )
        )
        or 0
    )
    return {
        "new": int(counts.get("new", 0)),
        "acknowledged": int(counts.get("acknowledged", 0)),
        "assigned": int(counts.get("assigned", 0)),
        "snoozed": int(counts.get("snoozed", 0)),
        "resolved": int(counts.get("resolved", 0)),
        "open": sum(int(counts.get(s, 0)) for s in _OPEN),
        "overdue_sla": overdue,
        "resolved_24h": resolved_24h,
    }
