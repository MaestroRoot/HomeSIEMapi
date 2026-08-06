"""Ukusanyaji wa takwimu kutoka `security_events` kwa dashboard."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import Device, SecurityEvent
from app.schemas.stats import (
    CountryCount,
    ScoreIssue,
    SecurityScore,
    StatsOverview,
    SuspiciousIndicator,
    TimeBucket,
    TopDomain,
    TopTalker,
    VerdictBreakdown,
)

_FLAGGED = ("malicious", "suspicious")
#: Ishara ya "flagged" kama namba 0/1, inatumika kwenye SUM/BOOL_OR.
_flagged_int = case((SecurityEvent.verdict.in_(_FLAGGED), 1), else_=0)


async def overview(db: AsyncSession, org_id: uuid.UUID) -> StatsOverview:
    org = SecurityEvent.organization_id == org_id
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    # --- hesabu kuu (query moja) ------------------------------------------
    totals = (
        await db.execute(
            select(
                func.count(SecurityEvent.id),
                func.coalesce(func.sum(_flagged_int), 0),
                func.count(func.distinct(SecurityEvent.domain)),
                func.count(func.distinct(SecurityEvent.dst_ip)),
            ).where(org)
        )
    ).one()
    total_events, flagged, unique_domains, unique_ips = (
        int(totals[0] or 0),
        int(totals[1] or 0),
        int(totals[2] or 0),
        int(totals[3] or 0),
    )

    events_24h = int(
        await db.scalar(
            select(func.count(SecurityEvent.id)).where(org, SecurityEvent.created_at >= since)
        )
        or 0
    )

    # --- mgawanyo wa verdict ---------------------------------------------
    verdict_rows = (
        await db.execute(
            select(SecurityEvent.verdict, func.count()).where(org).group_by(SecurityEvent.verdict)
        )
    ).all()
    bv = VerdictBreakdown()
    for verdict, count in verdict_rows:
        if hasattr(bv, verdict):
            setattr(bv, verdict, int(count))

    # --- top domains ------------------------------------------------------
    domain_rows = (
        await db.execute(
            select(
                SecurityEvent.domain,
                func.count().label("c"),
                func.bool_or(SecurityEvent.verdict.in_(_FLAGGED)),
            )
            .where(org, SecurityEvent.domain.isnot(None))
            .group_by(SecurityEvent.domain)
            .order_by(func.count().desc())
            .limit(12)
        )
    ).all()
    top_domains = [TopDomain(name=d, count=int(c), flagged=bool(f)) for d, c, f in domain_rows]

    # --- top talkers (kwa chanzo) ----------------------------------------
    talker_rows = (
        await db.execute(
            select(SecurityEvent.src_ip, func.count().label("c"))
            .where(org, SecurityEvent.src_ip.isnot(None))
            .group_by(SecurityEvent.src_ip)
            .order_by(func.count().desc())
            .limit(8)
        )
    ).all()
    top_talkers = [TopTalker(label=ip, count=int(c)) for ip, c in talker_rows]

    # --- viashiria vya mashaka -------------------------------------------
    susp_rows = (
        await db.execute(
            select(
                func.coalesce(SecurityEvent.domain, SecurityEvent.dst_ip).label("ind"),
                func.max(SecurityEvent.verdict).label("v"),
                func.max(SecurityEvent.country).label("country"),
                func.max(SecurityEvent.pulse_count).label("pulses"),
                func.count().label("c"),
            )
            .where(org, SecurityEvent.verdict.in_(_FLAGGED))
            .group_by(func.coalesce(SecurityEvent.domain, SecurityEvent.dst_ip))
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    suspicious = [
        SuspiciousIndicator(
            indicator=ind or "?",
            verdict=v,  # type: ignore[arg-type]
            country=country,
            pulse_count=int(pulses or 0),
            count=int(c),
        )
        for ind, v, country, pulses, c in susp_rows
        if ind
    ]

    # --- events kwa saa (masaa 24) ---------------------------------------
    bucket = func.date_trunc("hour", SecurityEvent.created_at)
    ot_rows = (
        await db.execute(
            select(
                bucket.label("h"),
                func.count().label("c"),
                func.coalesce(func.sum(_flagged_int), 0).label("f"),
            )
            .where(org, SecurityEvent.created_at >= since)
            .group_by(bucket)
            .order_by(bucket)
        )
    ).all()
    over_time = [
        TimeBucket(
            t=h.strftime("%H:%M") if isinstance(h, datetime) else str(h),
            events=int(c),
            flagged=int(f),
        )
        for h, c, f in ot_rows
    ]

    # --- kwa nchi ---------------------------------------------------------
    country_rows = (
        await db.execute(
            select(SecurityEvent.country, func.count().label("c"))
            .where(org, SecurityEvent.country.isnot(None))
            .group_by(SecurityEvent.country)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    by_country = [CountryCount(name=c, count=int(n)) for c, n in country_rows]

    # --- vifaa ------------------------------------------------------------
    total_devices = int(
        await db.scalar(select(func.count(Device.id)).where(Device.organization_id == org_id)) or 0
    )
    active_devices = int(
        await db.scalar(
            select(func.count(Device.id)).where(
                Device.organization_id == org_id,
                Device.last_seen_at >= now - timedelta(minutes=15),
            )
        )
        or 0
    )

    return StatsOverview(
        total_events=total_events,
        events24h=events_24h,
        flagged=flagged,
        unique_domains=unique_domains,
        unique_external_ips=unique_ips,
        total_devices=total_devices,
        active_devices=active_devices,
        by_verdict=bv,
        top_domains=top_domains,
        top_talkers=top_talkers,
        suspicious=suspicious,
        over_time=over_time,
        by_country=by_country,
    )


async def security_score(db: AsyncSession, org_id: uuid.UUID) -> SecurityScore:
    """0-100 posture score kutoka ishara halisi. Rahisi na wazi kwa makusudi,
    kila tatizo linatoa alama na jinsi ya kulirekebisha."""
    org = SecurityEvent.organization_id == org_id

    total = int(await db.scalar(select(func.count(SecurityEvent.id)).where(org)) or 0)
    malicious = int(
        await db.scalar(select(func.count(SecurityEvent.id)).where(org, SecurityEvent.verdict == "malicious"))
        or 0
    )
    suspicious = int(
        await db.scalar(select(func.count(SecurityEvent.id)).where(org, SecurityEvent.verdict == "suspicious"))
        or 0
    )
    distinct_flagged = int(
        await db.scalar(
            select(func.count(func.distinct(func.coalesce(SecurityEvent.domain, SecurityEvent.dst_ip)))).where(
                org, SecurityEvent.verdict.in_(_FLAGGED)
            )
        )
        or 0
    )
    risky_devices = int(
        await db.scalar(
            select(func.count(Device.id)).where(Device.organization_id == org_id, Device.risk_score >= 40)
        )
        or 0
    )
    devices = int(
        await db.scalar(select(func.count(Device.id)).where(Device.organization_id == org_id)) or 0
    )

    issues: list[ScoreIssue] = []
    score = 100

    if malicious > 0:
        impact = min(40, 15 + malicious * 5)
        score -= impact
        issues.append(
            ScoreIssue(
                title=f"{malicious} contact(s) with malicious indicators",
                impact=impact,
                severity="critical",
                detail="A device reached an indicator threat intelligence marks as malicious.",
                fix="Open Alerts, block the indicator, and inspect the device involved.",
            )
        )
    if suspicious > 0:
        impact = min(25, 5 + suspicious * 2)
        score -= impact
        issues.append(
            ScoreIssue(
                title=f"{suspicious} suspicious lookups/connections",
                impact=impact,
                severity="medium",
                detail="Devices contacted indicators seen in threat reports but not confirmed malicious.",
                fix="Review these in Alerts and corroborate before treating as confirmed.",
            )
        )
    if risky_devices > 0:
        impact = min(20, risky_devices * 8)
        score -= impact
        issues.append(
            ScoreIssue(
                title=f"{risky_devices} device(s) with an elevated risk score",
                impact=impact,
                severity="high",
                detail="These devices accumulated flagged activity.",
                fix="Investigate the device on the Devices page and clean up if needed.",
            )
        )
    if devices == 0:
        score -= 10
        issues.append(
            ScoreIssue(
                title="No devices are being monitored",
                impact=10,
                severity="medium",
                detail="Without a collector, HomeSIEM cannot see anything.",
                fix="Connect a sensor on the Devices page.",
            )
        )

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    if total == 0:
        summary = "No data yet. Connect a collector to start scoring your network."
    elif not issues:
        summary = "Nothing flagged. Your monitored traffic looks clean so far."
    else:
        summary = f"{len(issues)} issue(s) are pulling your score down. The fixes are listed below."

    return SecurityScore(score=score, grade=grade, summary=summary, issues=issues)
