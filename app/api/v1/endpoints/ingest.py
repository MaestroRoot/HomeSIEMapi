"""Ingest: sensor (box/agent) inatuma matukio, backend ina-enrich na kuhifadhi.

Auth ni **sensor token** (header `X-Sensor-Token`), si Firebase, kwa sababu
mtumaji ni kifaa, si mtu. Endpoint moja inahudumia sensor zote: tshark-live,
DNS resolver, au chochote kinachotuma umbo la `IngestEvent`.

Enrichment ni ile ile ya PcapUpload: GeoIP kwa kila IP ya nje (bure), OTX kwa
domain/IP (kwa cache ili stream isipige OTX kwa domain ile ile mara kwa mara).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.api.deps import DbSession, SensorOrg
from app.core import geoip, notify, threatintel
from app.core.config import settings
from app.core.logging import get_logger
from app.crud import detection as detection_crud
from app.crud import monitoring as crud
from app.crud import notification as notification_crud
from app.models.monitoring import ForensicSnapshot, LogEntry, SecurityEvent, Vulnerability
from app.schemas.common import Message
from app.schemas.intel import GeoLocation
from app.schemas.monitoring import IngestBatch, IngestResult
from app.schemas.telemetry import ForensicIn, LogBatch, ScanResult

logger = get_logger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _occurred(ts: float | None) -> datetime | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


@router.post("/events", response_model=IngestResult, summary="Sensor event ingest")
async def ingest_events(batch: IngestBatch, org_id: SensorOrg, db: DbSession) -> IngestResult:
    flagged = 0
    rule_hits = 0
    touched: set = set()
    now = datetime.now(timezone.utc)

    # Kwa arifa: mistari ya matukio yaliyoflag na severity kubwa zaidi.
    flagged_lines: list[str] = []
    max_sev = "info"
    _rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    # Rules zinapakuliwa mara moja kwa batch, kisha zinatathminiwa kwa kila event.
    rules = await detection_crud.list_rules(db, org_id)

    for ev in batch.events:
        # --- GeoIP kwa destination (kwa flow) ---------------------------
        geo: GeoLocation | None = None
        if ev.dst_ip and settings.geoip_enabled:
            geo = geoip.lookup(ev.dst_ip)

        # --- OTX: domain (dns) au destination ya nje (flow) -------------
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

        # --- Map kwa device --------------------------------------------
        device = await crud.match_or_create_device(
            db, org_id, mac=ev.src_mac, ip=ev.src_ip
        )
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

        # Tathmini detection rules, zinaweza kupandisha severity ya event.
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
        len(batch.events),
        flagged,
        rule_hits,
        len(touched),
        org_id,
    )

    # Arifa: kama kuna flagged, tuma muhtasari kwa channels zinazolingana.
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

    return IngestResult(accepted=len(batch.events), flagged=flagged, devices_touched=len(touched))


@router.post("/logs", response_model=Message, summary="Log agent ingest")
async def ingest_logs(batch: LogBatch, org_id: SensorOrg, db: DbSession) -> Message:
    for e in batch.entries:
        occurred = _occurred(e.ts)
        # Postgres TEXT haiwezi kuhifadhi NULL byte (0x00); Windows Event Log
        # huweka moja mwisho wa kila message. Tunaisafisha.
        message = e.message.replace("\x00", "").strip()[:8000]
        db.add(
            LogEntry(
                organization_id=org_id,
                source=e.source.replace("\x00", "")[:64],
                host=e.host.replace("\x00", "")[:120] if e.host else None,
                level=e.level,
                message=message,
                occurred_at=occurred,
            )
        )
    await db.commit()
    return Message(detail=f"{len(batch.entries)} log entries stored.", code="logs_stored")


@router.post("/scan", response_model=Message, summary="Vulnerability scan results ingest")
async def ingest_scan(result: ScanResult, org_id: SensorOrg, db: DbSession) -> Message:
    # Matokeo mapya ya target huyu yanachukua nafasi ya ya zamani.
    from sqlalchemy import delete

    await db.execute(
        delete(Vulnerability).where(
            Vulnerability.organization_id == org_id, Vulnerability.target == result.target
        )
    )
    for f in result.findings:
        db.add(
            Vulnerability(
                organization_id=org_id,
                target=result.target,
                port=f.port,
                service=f.service,
                severity=f.severity,
                title=f.title[:200],
                detail=f.detail,
                fix=f.fix,
            )
        )
    await db.commit()
    return Message(detail=f"{len(result.findings)} findings stored for {result.target}.", code="scan_stored")


@router.post("/forensics", response_model=Message, summary="Forensic snapshot ingest")
async def ingest_forensics(snap: ForensicIn, org_id: SensorOrg, db: DbSession) -> Message:
    db.add(
        ForensicSnapshot(
            organization_id=org_id,
            host=snap.host,
            processes=snap.processes,
            connections=snap.connections,
        )
    )
    await db.commit()
    return Message(detail=f"Snapshot for {snap.host} stored.", code="forensics_stored")
