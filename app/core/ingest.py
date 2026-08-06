"""Enrichment + kuhifadhi kwa matukio ya sensor.

Logic hii ilikuwa ndani ya endpoint ya `/ingest/events`. Imetolewa hapa ili
itumike pia na poller ya ndani (mfano NextDNS) bila kupitia HTTP/token —
inaingiza moja kwa moja kwa org husika.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Protocol

from app.core import geoip, notify, threatintel
from app.core.config import settings
from app.core.logging import get_logger
from app.crud import detection as detection_crud
from app.crud import monitoring as crud
from app.crud import notification as notification_crud
from app.models.monitoring import SecurityEvent
from app.schemas.intel import GeoLocation

logger = get_logger(__name__)


class _Event(Protocol):
    kind: str
    src_ip: str | None
    src_mac: str | None
    domain: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    ts: float | None


def _occurred(ts: float | None) -> datetime | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


async def ingest_security_events(
    db, org_id: uuid.UUID, events: list[_Event]
) -> tuple[int, int, int]:
    """Enrich (GeoIP + OTX), map kwa device, tathmini rules, hifadhi, arifa.

    Inarudisha (accepted, flagged, devices_touched).
    """
    flagged = 0
    rule_hits = 0
    touched: set = set()
    now = datetime.now(timezone.utc)

    flagged_lines: list[str] = []
    max_sev = "info"
    _rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    rules = await detection_crud.list_rules(db, org_id)

    for ev in events:
        geo: GeoLocation | None = None
        if ev.dst_ip and settings.geoip_enabled:
            geo = geoip.lookup(ev.dst_ip)

        verdict = "unknown"
        pulse_count = 0
        if settings.otx_enabled:
            target = None
            if ev.kind == "dns" and ev.domain:
                target = (ev.domain, "domain")
            elif ev.dst_ip and not (geo and geo.is_private):
                target = (ev.dst_ip, "ip")
            if target is not None:
                try:
                    res = await threatintel.lookup_cached(target[0], target[1])  # type: ignore[arg-type]
                    verdict, pulse_count = res.verdict, res.pulse_count
                except Exception as exc:  # noqa: BLE001
                    logger.warning("OTX enrichment imeshindwa kwa %s: %s", target[0], exc)

        is_flagged = verdict in ("malicious", "suspicious")
        if is_flagged:
            flagged += 1

        device = await crud.match_or_create_device(db, org_id, mac=ev.src_mac, ip=ev.src_ip)
        occurred = _occurred(ev.ts)

        event = SecurityEvent(
            organization_id=org_id,
            device_id=device.id if device is not None else None,
            kind=ev.kind,
            src_ip=ev.src_ip,
            src_mac=crud.normalize_mac(ev.src_mac),
            domain=ev.domain,
            dst_ip=ev.dst_ip,
            dst_port=ev.dst_port,
            protocol=ev.protocol,
            verdict=verdict,
            severity=crud.severity_for(verdict),
            pulse_count=pulse_count,
            country=geo.country if geo else None,
            asn=geo.asn if geo else None,
            asn_org=geo.asn_org if geo else None,
            occurred_at=occurred,
        )

        matched = detection_crud.evaluate(rules, event)
        if matched:
            rule_hits += len(matched)
            is_flagged = True

        if is_flagged:
            indicator = event.domain or event.dst_ip or "?"
            src = event.src_ip or "device"
            flagged_lines.append(f"[{event.verdict}] {src} -> {indicator} ({event.country or 'unknown'})")
            if _rank.get(event.severity, 0) > _rank.get(max_sev, 0):
                max_sev = event.severity

        if device is not None:
            crud.touch_device(device, ip=ev.src_ip, when=occurred or now, flagged=is_flagged)
            touched.add(device.id)

        db.add(event)

    await db.commit()
    logger.info(
        "Ingest: %s matukio, %s flagged, %s rule-hits, devices %s (org=%s)",
        len(events), flagged, rule_hits, len(touched), org_id,
    )

    if flagged_lines:
        channels = await notification_crud.enabled_channels(db, org_id)
        matching = [c for c in channels if notify.severity_meets(max_sev, c.min_severity)]
        if matching:
            subject = f"HomeSIEM: {len(flagged_lines)} flagged event(s) [{max_sev}]"
            message = "\n".join(flagged_lines[:20])
            sent = []
            for c in matching:
                if await notify.send_alert(ch_type=c.type, target=c.target, subject=subject, message=message):
                    sent.append(c)
            await notification_crud.mark_sent(db, sent)

    return len(events), flagged, len(touched)
