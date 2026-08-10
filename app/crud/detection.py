"""Detection rules: CRUD na tathmini (evaluation) juu ya events."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
    description: str = "",
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    window_seconds: int = 0,
    group_by: str = "",
    threshold: int = 1,
) -> DetectionRule:
    rule = DetectionRule(
        organization_id=organization_id,
        name=name.strip(),
        description=description,
        condition_type=condition_type,
        value=value.strip(),
        severity=severity,
        action=action,
        source=source,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        window_seconds=window_seconds,
        group_by=group_by,
        threshold=threshold,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(db: AsyncSession, rule: DetectionRule, **fields) -> DetectionRule:
    for key, val in fields.items():
        if val is None:
            continue
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
    if ct == "kind_is":
        return event.kind == v or (event.event_type or "") == v
    if ct == "pulse_count_gte":
        try:
            return event.pulse_count >= int(v)
        except ValueError:
            return False
    return False


def _group_value(rule: DetectionRule, event: SecurityEvent) -> str:
    g = rule.group_by
    if g == "dst_ip":
        return event.dst_ip or ""
    if g == "src_ip":
        return event.src_ip or ""
    if g == "domain":
        return event.domain or ""
    if g == "device_id":
        return str(event.device_id) if event.device_id else ""
    if g == "account":
        return event.account or ""
    if g == "process":
        return event.process_name or ""
    if g == "source":
        return event.source or ""
    if g == "country":
        return event.country or ""
    return ""


#: Ngazi ya severity ili tuchague kubwa zaidi.
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def evaluate(rules: list[DetectionRule], event: SecurityEvent) -> list[DetectionRule]:
    """Tathmini rules (zilizowashwa, zisizo za correlation) dhidi ya event moja.

    Inaongeza `hits`, inaweka `last_hit_at`, na inapandisha severity ya event
    kufikia ile ya rule iliyolingana yenye kiwango cha juu. Hairudishi commit,
    mwitaji ndiye ana-commit. Inarudisha rules zilizolingana.
    """
    matched: list[DetectionRule] = []
    now = datetime.now(timezone.utc)
    for rule in rules:
        if not rule.enabled or rule.window_seconds > 0:
            continue
        if _matches(rule, event):
            rule.hits = (rule.hits or 0) + 1
            rule.last_hit_at = now
            matched.append(rule)
            if _RANK.get(rule.severity, 0) > _RANK.get(event.severity, 0):
                event.severity = rule.severity
    return matched


async def evaluate_correlation(
    db: AsyncSession,
    organization_id: uuid.UUID,
    rule: DetectionRule,
    event: SecurityEvent,
) -> bool:
    """Tathmini rule ya correlation: hesabu matukio yanayolingana ndani ya
    `window_seconds`, yakipangwa kwa `group_by`. Inarudisha True kama idadi
    (ikiwa ni pamoja na event hii) inazidi `threshold`."""
    if not rule.enabled or rule.window_seconds <= 0:
        return False
    if not _matches(rule, event):
        return False

    since = datetime.now(timezone.utc) - timedelta(seconds=rule.window_seconds)
    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.organization_id == organization_id,
            SecurityEvent.occurred_at.isnot(None),
            SecurityEvent.occurred_at >= since,
        )
        .limit(20000)
    )
    recent = list((await db.execute(stmt)).scalars())

    group = _group_value(rule, event)
    # Rule zisizo na group_by huhesabia matukio yote yanayolingana.
    count = 1
    for ev in recent:
        if ev.id == event.id:
            continue
        if not _matches(rule, ev):
            continue
        if group and _group_value(rule, ev) != group:
            continue
        count += 1
    return count >= rule.threshold


def event_indicator(event: SecurityEvent) -> str:
    """Kiashiria kikuu cha event (domain/IP/account/process) kwa ajili ya alerts."""
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

