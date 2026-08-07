"""UEBA scoring engine — inakusanya data kutoka modules zote na kugundua anomalies.

Inatumia:
- SecurityEvent (Cloudflare DNS + network flows)
- ForensicSnapshot (processes per device)
- Incident (alerts zilizopita)
- Device (owner_name mapping)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import Device, SecurityEvent, ForensicSnapshot, Incident
from app.models.ueva import UserAnomaly
from app.crud.ueva import (
    create_anomaly,
    get_baseline,
    upsert_baseline,
    upsert_risk_score,
)


# --- Scoring weights ------------------------------------------------------

WEIGHTS = {
    "unusual_hour": 20,
    "new_domain": 15,
    "suspicious_domain": 25,
    "data_spike": 20,
    "unusual_process": 15,
    "new_connection": 10,
    "alert_triggered": 15,
    "high_severity_alert": 25,
    "forensic_suspicious": 20,
}

SEVERITY_SCORES = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}

SUSPICIOUS_DOMAINS = {
    "malware", "phishing", "c2", "botnet", "tor", "vpn",
    "crypto", "mining", "exploit", "hack", "crack",
}


# --- Helpers ---------------------------------------------------------------


def _hour_is_unusual(hour: int, normal_hours: dict) -> bool:
    """Je, saa hii ni ya kawaida kwa mtumiaji?"""
    if not normal_hours:
        return False
    start = normal_hours.get("start", 7)
    end = normal_hours.get("end", 19)
    if start <= end:
        return hour < start or hour >= end
    # Usiku (mfano: start=22, end=6)
    return hour < start and hour >= end


def _domain_is_suspicious(domain: str) -> bool:
    """Je, domain inaashiria kitu hatari?"""
    domain_lower = domain.lower()
    return any(kw in domain_lower for kw in SUSPICIOUS_DOMAINS)


def _domain_is_new(domain: str, normal_domains: list) -> bool:
    """Je, domain hii ni mpya kwa mtumiaji?"""
    if not normal_domains:
        return False
    return domain.lower() not in [d.lower() for d in normal_domains]


def _process_is_unusual(process_name: str, normal_processes: list) -> bool:
    """Je, programu hii ni ya kawaida kwa mtumiaji?"""
    if not normal_processes:
        return False
    return process_name.lower() not in [p.lower() for p in normal_processes]


# --- Main engine -----------------------------------------------------------


async def analyze_owner(
    db: AsyncSession,
    organization_id: uuid.UUID,
    owner_name: str,
) -> list[dict]:
    """Chunguza tabia ya mtumiaji na rudisha anomalies mpya.

    Returns: list ya anomalies mpya zilizogunduliwa.
    """
    anomalies = []

    # 1. Pata devices za mtumiaji
    devices_stmt = select(Device).where(
        Device.organization_id == organization_id,
        Device.owner_name == owner_name,
    )
    devices = list((await db.execute(devices_stmt)).scalars())
    if not devices:
        return []

    device_ids = [d.id for d in devices]
    device_names = {d.id: d.name for d in devices}

    # 2. Pata baseline
    baseline = await get_baseline(db, organization_id, owner_name)

    # 3. SecurityEvents za siku 24 zilizopita
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    events_stmt = select(SecurityEvent).where(
        SecurityEvent.organization_id == organization_id,
        SecurityEvent.device_id.in_(device_ids),
        SecurityEvent.created_at >= since,
    )
    events = list((await db.execute(events_stmt)).scalars())

    # 4. ForensicSnapshots za siku 24
    for device in devices:
        fs_stmt = select(ForensicSnapshot).where(
            ForensicSnapshot.organization_id == organization_id,
            ForensicSnapshot.host == device.hostname or ForensicSnapshot.host == device.name,
        ).order_by(ForensicSnapshot.created_at.desc()).limit(1)
        fs = (await db.execute(fs_stmt)).scalar_one_or_none()
        if not fs:
            continue

        device_name = device_names.get(device.id, "unknown")

        # Check processes
        for proc in (fs.processes or []):
            proc_name = proc.get("name", "")
            proc_user = proc.get("user", "")

            # Process is unusual
            if baseline and _process_is_unusual(proc_name, baseline.normal_processes):
                anomalies.append({
                    "owner_name": owner_name,
                    "anomaly_type": "unusual_process",
                    "severity": "medium",
                    "risk_score": WEIGHTS["unusual_process"],
                    "description": f"User ran unusual process '{proc_name}' on {device_name}",
                    "evidence": {"process": proc_name, "device": device_name, "user": proc_user},
                    "device_name": device_name,
                })

    # 5. Events — check each
    for event in events:
        device_name = device_names.get(event.device_id, "unknown")

        # Unusual hour
        if event.occurred_at and baseline:
            hour = event.occurred_at.hour
            if _hour_is_unusual(hour, baseline.normal_hours):
                anomalies.append({
                    "owner_name": owner_name,
                    "anomaly_type": "unusual_hour",
                    "severity": "medium",
                    "risk_score": WEIGHTS["unusual_hour"],
                    "description": f"Activity at unusual hour ({hour}:00) on {device_name}",
                    "evidence": {
                        "hour": hour,
                        "device": device_name,
                        "domain": event.domain,
                        "dst_ip": event.dst_ip,
                    },
                    "device_name": device_name,
                })

        # New domain
        if event.domain and baseline and _domain_is_new(event.domain, baseline.normal_domains):
            anomalies.append({
                "owner_name": owner_name,
                "anomaly_type": "new_domain",
                "severity": "low",
                "risk_score": WEIGHTS["new_domain"],
                "description": f"Visited new domain '{event.domain}' on {device_name}",
                "evidence": {"domain": event.domain, "device": device_name},
                "device_name": device_name,
            })

        # Suspicious domain
        if event.domain and _domain_is_suspicious(event.domain):
            anomalies.append({
                "owner_name": owner_name,
                "anomaly_type": "suspicious_domain",
                "severity": "high",
                "risk_score": WEIGHTS["suspicious_domain"],
                "description": f"Visited suspicious domain '{event.domain}' on {device_name}",
                "evidence": {"domain": event.domain, "verdict": event.verdict, "device": device_name},
                "device_name": device_name,
            })

    # 6. Incidents za siku 7 zilizopita
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    incident_stmt = select(Incident).where(
        Incident.organization_id == organization_id,
        Incident.created_at >= week_ago,
    )
    incidents = list((await db.execute(incident_stmt)).scalars())

    for incident in incidents:
        # Check if incident notes mention this owner
        notes_text = " ".join(
            str(n.get("body", "")) for n in (incident.notes or []) if isinstance(n, dict)
        )
        if owner_name.lower() in notes_text.lower() or owner_name.lower() in (incident.title or "").lower():
            sev = incident.severity
            score = SEVERITY_SCORES.get(sev, 10)
            anomalies.append({
                "owner_name": owner_name,
                "anomaly_type": "alert_triggered",
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "risk_score": score,
                "description": f"Incident '{incident.title}' mentions this user",
                "evidence": {"incident_id": str(incident.id), "title": incident.title, "severity": sev},
                "device_name": None,
            })

    # 7. Save anomalies
    saved = []
    for a in anomalies:
        created = await create_anomaly(
            db,
            organization_id=organization_id,
            owner_name=a["owner_name"],
            anomaly_type=a["anomaly_type"],
            severity=a["severity"],
            risk_score=a["risk_score"],
            description=a["description"],
            evidence=a["evidence"],
            device_name=a.get("device_name"),
        )
        saved.append(created)

    # 8. Calculate total risk score
    open_stmt = select(func.coalesce(func.sum(UserAnomaly.risk_score), 0)).where(
        UserAnomaly.organization_id == organization_id,
        UserAnomaly.owner_name == owner_name,
        UserAnomaly.status == "open",
    )

    # Simpler: just count from the anomalies we just created
    total_score = sum(a["risk_score"] for a in anomalies if a["severity"] in ("critical", "high"))
    total_score += sum(a["risk_score"] // 2 for a in anomalies if a["severity"] == "medium")
    total_score = min(100, total_score)

    open_count = len([a for a in anomalies])
    total_count = open_count  # For now, all are new

    await upsert_risk_score(
        db, organization_id, owner_name, total_score, open_count, total_count
    )

    return saved


async def build_baseline(
    db: AsyncSession,
    organization_id: uuid.UUID,
    owner_name: str,
) -> None:
    """Jenga baseline kutoka data ya siku 14 za historia."""
    # Pata devices
    devices_stmt = select(Device).where(
        Device.organization_id == organization_id,
        Device.owner_name == owner_name,
    )
    devices = list((await db.execute(devices_stmt)).scalars())
    if not devices:
        return

    device_ids = [d.id for d in devices]

    # Events za siku 14
    since = datetime.now(timezone.utc) - timedelta(days=14)
    events_stmt = select(SecurityEvent).where(
        SecurityEvent.organization_id == organization_id,
        SecurityEvent.device_id.in_(device_ids),
        SecurityEvent.created_at >= since,
    )
    events = list((await db.execute(events_stmt)).scalars())

    if not events:
        return

    # Calculate baselines
    hours = defaultdict(int)
    domains = defaultdict(int)
    processes = defaultdict(int)

    for event in events:
        if event.occurred_at:
            hours[event.occurred_at.hour] += 1
        if event.domain:
            domains[event.domain.lower()] += 1

    # Get processes from forensics
    for device in devices:
        fs_stmt = select(ForensicSnapshot).where(
            ForensicSnapshot.organization_id == organization_id,
            ForensicSnapshot.host == device.hostname or ForensicSnapshot.host == device.name,
        ).order_by(ForensicSnapshot.created_at.desc()).limit(5)
        snapshots = list((await db.execute(fs_stmt)).scalars())
        for fs in snapshots:
            for proc in (fs.processes or []):
                pname = proc.get("name", "")
                if pname:
                    processes[pname] += 1

    # Normal hours: hours with >10% of total activity
    total_events = len(events)
    active_hours = {h for h, c in hours.items() if c / max(total_events, 1) > 0.05}
    normal_start = min(active_hours) if active_hours else 7
    normal_end = max(active_hours) + 1 if active_hours else 19

    # Normal domains: top 20
    sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
    normal_domains = [d for d, _ in sorted_domains[:20]]

    # Normal processes: top 15
    sorted_procs = sorted(processes.items(), key=lambda x: x[1], reverse=True)
    normal_processes = [p for p, _ in sorted_procs[:15]]

    await upsert_baseline(
        db,
        organization_id,
        owner_name,
        normal_hours={"start": normal_start, "end": normal_end},
        normal_processes=normal_processes,
        normal_domains=normal_domains,
        avg_daily_bytes=0,  # TODO: calculate from flows
        avg_daily_connections=len(events) // 14,
    )
