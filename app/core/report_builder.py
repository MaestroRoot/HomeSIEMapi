"""Kujenga na kutuma ripoti kutoka data halisi (kwa scheduled reports).

Frontend inajenga sections zake kwa lookups zake; hapa backend inafanya vivyo
ili worker ya ratiba iweze kutuma bila browser.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.email import send_report_email
from app.core.logging import get_logger
from app.crud import monitoring as mon_crud
from app.crud import stats as stats_crud
from app.crud import user as user_crud
from app.models.monitoring import Vulnerability

logger = get_logger(__name__)

_TITLES = {
    "weekly": "Weekly security report",
    "monthly": "Monthly security report",
    "executive": "Executive summary",
    "incident": "Incident report",
}


async def build_sections(db: AsyncSession, org_id: uuid.UUID) -> list[tuple[str, str]]:
    stats = await stats_crud.overview(db, org_id)
    score = await stats_crud.security_score(db, org_id)
    ev_rows, _ = await mon_crud.list_events(db, org_id, limit=15, only_flagged=True)
    devices, _ = await mon_crud.list_devices(db, org_id, limit=100)
    vulns = list(
        (
            await db.execute(
                select(Vulnerability).where(Vulnerability.organization_id == org_id).limit(30)
            )
        ).scalars()
    )

    sections: list[tuple[str, str]] = []
    sections.append((
        "Executive summary",
        f"Security score: {score.score}/100 (grade {score.grade}). {score.summary} "
        f"Total events: {stats.total_events} ({stats.events24h} in the last 24h). "
        f"Flagged: {stats.flagged}. Devices: {stats.active_devices}/{stats.total_devices} active.",
    ))
    if score.issues:
        sections.append((
            "Issues affecting your score",
            "\n".join(f"- [{i.severity}] {i.title} (-{i.impact}). Fix: {i.fix}" for i in score.issues),
        ))
    sections.append((
        "Flagged indicators",
        "\n".join(f"- {s.indicator} [{s.verdict}] {s.country or ''} - {s.pulse_count} reports"
                  for s in stats.suspicious) or "None flagged in this period.",
    ))
    if ev_rows:
        sections.append((
            "Recent flagged events",
            "\n".join(f"- {ev.created_at:%Y-%m-%d %H:%M} {name or ev.src_ip} -> {ev.domain or ev.dst_ip} [{ev.verdict}]"
                      for ev, name in ev_rows),
        ))
    sections.append((
        "Devices",
        "\n".join(f"- {d.name} ({d.mac or d.last_ip or '-'}) risk {d.risk_score}, {d.events_count} events"
                  for d in devices) or "No devices monitored yet.",
    ))
    if vulns:
        sections.append((
            "Vulnerabilities",
            "\n".join(f"- [{v.severity}] {v.target}:{v.port or ''} {v.service or ''} - {v.title}" for v in vulns),
        ))
    return sections


def render_html(sections: list[tuple[str, str]]) -> str:
    parts = []
    for heading, body in sections:
        safe = body.replace("\n", "<br />")
        parts.append(
            f'<h2 style="font-size:15px;color:#0f172a;margin:20px 0 6px;">{heading}</h2>'
            f'<p style="margin:0;color:#334155;">{safe}</p>'
        )
    return "".join(parts)


async def send_report_now(db: AsyncSession, org_id: uuid.UUID, *, kind: str, period: str,
                          recipients: list[str], to_whole_team: bool) -> tuple[list[str], list[str]]:
    """Jenga ripoti na uituma. Inarudisha (sent, failed)."""
    emails = [e.lower() for e in recipients]
    if to_whole_team:
        members, _ = await user_crud.list_by_organization(db, org_id, limit=200)
        emails.extend(m.email for m in members if m.is_active)
    emails = list(dict.fromkeys(emails))
    if not emails:
        return [], []

    sections = await build_sections(db, org_id)
    html = render_html(sections)
    title = _TITLES.get(kind, "Security report")
    sent: list[str] = []
    failed: list[str] = []
    for email in emails:
        ok = await send_report_email(to_email=email, to_name=None, title=title, period=period, summary_html=html)
        (sent if ok else failed).append(email)
    return sent, failed
