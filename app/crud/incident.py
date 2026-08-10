"""CRUD ya incidents."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.monitoring import Incident
from app.models.siem import Alert


async def list_incidents(db: AsyncSession, organization_id: uuid.UUID) -> list[Incident]:
    stmt = (
        select(Incident)
        .where(Incident.organization_id == organization_id)
        .order_by(Incident.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def get_incident(
    db: AsyncSession, organization_id: uuid.UUID, incident_id: uuid.UUID
) -> Incident | None:
    stmt = select(Incident).where(
        Incident.id == incident_id, Incident.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_incident(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    title: str,
    severity: str,
    summary: str,
    assignee: str | None,
    alert_ids: list[str] | None = None,
    entity_values: list[dict] | None = None,
) -> Incident:
    inc = Incident(
        organization_id=organization_id,
        title=title.strip(),
        severity=severity,
        summary=summary,
        assignee=assignee,
        status="new",
        notes=[],
        timeline=[
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "type": "created",
                "actor": "system",
                "message": "Incident imeundwa",
            }
        ],
        entities=entity_values or [],
        alert_ids=[],
    )
    db.add(inc)
    await db.flush()
    for alert_id in alert_ids or []:
        try:
            await link_alert_to_incident(db, inc, uuid.UUID(alert_id), flush=True)
        except Exception:  # noqa: BLE001 — alert ya org nyingine haitoki kuunganishwa.
            pass
    await db.commit()
    await db.refresh(inc)
    return inc


async def update_incident(
    db: AsyncSession,
    inc: Incident,
    *,
    status: str | None = None,
    severity: str | None = None,
    assignee: str | None = None,
    summary: str | None = None,
    note: str | None = None,
    note_author: str = "system",
) -> Incident:
    if status is not None:
        inc.status = status
    if severity is not None:
        inc.severity = severity
    if assignee is not None:
        inc.assignee = assignee or None
    if summary is not None:
        inc.summary = summary
    if note:
        inc.notes = [
            *inc.notes,
            {
                "author": note_author,
                "time": datetime.now(timezone.utc).isoformat(),
                "body": note.strip(),
            },
        ]
        flag_modified(inc, "notes")
        await add_timeline_event(
            db,
            inc,
            type="note",
            author=note_author,
            message="Dokezo limeongezwa",
            commit=False,
        )
    await db.commit()
    await db.refresh(inc)
    return inc


async def count_open(db: AsyncSession, organization_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count(Incident.id)).where(
                Incident.organization_id == organization_id, Incident.status != "closed"
            )
        )
        or 0
    )


async def add_timeline_event(
    db: AsyncSession,
    inc: Incident,
    *,
    type: str,
    message: str,
    author: str = "system",
    commit: bool = True,
) -> Incident:
    inc.timeline = [
        *inc.timeline,
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "type": type,
            "actor": author,
            "message": message,
        },
    ]
    flag_modified(inc, "timeline")
    if commit:
        await db.commit()
        await db.refresh(inc)
    return inc


async def add_entities(db: AsyncSession, inc: Incident, entities: list[dict]) -> Incident:
    merged = {frozenset(e.items()): e for e in (inc.entities or [])}
    for entity in entities:
        if not entity:
            continue
        merged[frozenset(entity.items())] = entity
    inc.entities = list(merged.values())
    flag_modified(inc, "entities")
    await db.commit()
    await db.refresh(inc)
    return inc


async def link_alert_to_incident(
    db: AsyncSession, inc: Incident, alert_id: uuid.UUID, flush: bool = False
) -> bool:
    """Unganisha alert na incident (kama bado haijaunganishwa). Inarudisha True
    kama imefanikiwa (alert ni ya org moja na haiko kwenye incident nyingine wazi)."""
    if str(alert_id) in (inc.alert_ids or []):
        return True
    alert = await db.get(Alert, alert_id)
    if alert is None or alert.organization_id != inc.organization_id:
        return False
    if alert.incident_id is not None and str(alert.incident_id) != str(inc.id):
        return False
    inc.alert_ids = [*(inc.alert_ids or []), str(alert_id)]
    flag_modified(inc, "alert_ids")
    alert.incident_id = inc.id
    if inc.status != "closed":
        alert.status = "assigned"
    if not flush:
        await db.commit()
        await db.refresh(inc)
    return True


async def unlink_alert_from_incident(
    db: AsyncSession, inc: Incident, alert_id: uuid.UUID
) -> bool:
    if str(alert_id) not in (inc.alert_ids or []):
        return False
    inc.alert_ids = [a for a in (inc.alert_ids or []) if a != str(alert_id)]
    flag_modified(inc, "alert_ids")
    alert = await db.get(Alert, alert_id)
    if alert is not None and alert.incident_id == inc.id:
        alert.incident_id = None
    await db.commit()
    await db.refresh(inc)
    return True
