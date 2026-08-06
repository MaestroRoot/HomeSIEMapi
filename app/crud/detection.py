"""Detection rules: CRUD na tathmini (evaluation) juu ya events."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import DetectionRule, SecurityEvent


async def list_rules(db: AsyncSession, organization_id: uuid.UUID) -> list[DetectionRule]:
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.organization_id == organization_id)
        .order_by(DetectionRule.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def get_rule(
    db: AsyncSession, organization_id: uuid.UUID, rule_id: uuid.UUID
) -> DetectionRule | None:
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id, DetectionRule.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_rule(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    name: str,
    condition_type: str,
    value: str,
    severity: str,
    action: str,
    source: str = "custom",
) -> DetectionRule:
    rule = DetectionRule(
        organization_id=organization_id,
        name=name.strip(),
        condition_type=condition_type,
        value=value.strip(),
        severity=severity,
        action=action,
        source=source,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(db: AsyncSession, rule: DetectionRule, **fields) -> DetectionRule:
    for key, val in fields.items():
        if val is not None:
            setattr(rule, key, val.strip() if isinstance(val, str) else val)
    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_rule(db: AsyncSession, rule: DetectionRule) -> None:
    await db.delete(rule)
    await db.commit()


async def count_rules(db: AsyncSession, organization_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.organization_id == organization_id
            )
        )
        or 0
    )


# --- evaluation -----------------------------------------------------------


def _matches(rule: DetectionRule, event: SecurityEvent) -> bool:
    ct, v = rule.condition_type, rule.value
    if ct == "verdict_is":
        return event.verdict == v
    if ct == "domain_contains":
        return bool(event.domain) and v.lower() in event.domain.lower()
    if ct == "country_is":
        return bool(event.country) and v.lower() == event.country.lower()
    if ct == "pulse_count_gte":
        try:
            return event.pulse_count >= int(v)
        except ValueError:
            return False
    return False


#: Ngazi ya severity ili tuchague kubwa zaidi.
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate(rules: list[DetectionRule], event: SecurityEvent) -> list[DetectionRule]:
    """Tathmini rules zote (zilizowashwa) dhidi ya event moja.

    Inaongeza `hits`, inaweka `last_hit_at`, na inapandisha severity ya event
    kufikia ile ya rule iliyolingana yenye kiwango cha juu. Hairudishi commit,
    mwitaji ndiye ana-commit. Inarudisha rules zilizolingana.
    """
    matched: list[DetectionRule] = []
    now = datetime.now(timezone.utc)
    for rule in rules:
        if not rule.enabled:
            continue
        if _matches(rule, event):
            rule.hits = (rule.hits or 0) + 1
            rule.last_hit_at = now
            matched.append(rule)
            if _RANK.get(rule.severity, 0) > _RANK.get(event.severity, 0):
                event.severity = rule.severity
    return matched
