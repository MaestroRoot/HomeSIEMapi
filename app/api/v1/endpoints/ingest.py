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
from app.core.ingest import ingest_security_events
from app.core.logging import get_logger
from app.models.monitoring import ForensicSnapshot, LogEntry, Vulnerability
from app.schemas.common import Message
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
    accepted, flagged, touched = await ingest_security_events(db, org_id, batch.events)
    return IngestResult(accepted=accepted, flagged=flagged, devices_touched=touched)


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
