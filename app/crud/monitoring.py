"""Shughuli za database kwa devices, matukio, na sensor tokens."""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import Integer, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import Device, SecurityEvent, SensorToken

_MAC_RE = re.compile(r"[^0-9a-f]")

#: verdict -> severity kwa UI. OTX pekee haitoi "malicious", hivyo kubwa zaidi
#: ni "suspicious" -> "medium" mpaka feed ya pili itakapoongezwa.
_SEVERITY: dict[str, str] = {
    "malicious": "high",
    "suspicious": "medium",
    "clean": "info",
    "unknown": "info",
}


def severity_for(verdict: str) -> str:
    return _SEVERITY.get(verdict, "info")


def normalize_mac(mac: str | None) -> str | None:
    """"AA-BB-CC-DD-EE-FF" / "aabb.ccdd.eeff" -> "aa:bb:cc:dd:ee:ff"."""
    if not mac:
        return None
    hexed = _MAC_RE.sub("", mac.lower())
    if len(hexed) != 12:
        return None
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2))


# --- Devices --------------------------------------------------------------


async def list_devices(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int = 200, offset: int = 0
) -> tuple[list[Device], int]:
    total = await db.scalar(
        select(func.count(Device.id)).where(Device.organization_id == organization_id)
    )
    stmt = (
        select(Device)
        .where(Device.organization_id == organization_id)
        .order_by(Device.last_seen_at.desc().nulls_last(), Device.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list((await db.execute(stmt)).scalars())
    return rows, int(total or 0)


async def get_device(
    db: AsyncSession, organization_id: uuid.UUID, device_id: uuid.UUID
) -> Device | None:
    stmt = select(Device).where(
        Device.id == device_id, Device.organization_id == organization_id
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def register_device(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    name: str,
    mac: str | None,
    device_type: str,
    last_ip: str | None,
    hostname: str | None,
    owner_name: str | None = None,
) -> Device:
    mac_norm = normalize_mac(mac)
    # Kama MAC ipo tayari (imegunduliwa awali), sasishe badala ya kurudia.
    existing = None
    if mac_norm:
        existing = (
            await db.execute(
                select(Device).where(
                    Device.organization_id == organization_id, Device.mac == mac_norm
                )
            )
        ).scalar_one_or_none()

    if existing is not None:
        existing.name = name
        existing.device_type = device_type
        existing.discovered = False
        if last_ip:
            existing.last_ip = last_ip
        if hostname:
            existing.hostname = hostname
        if owner_name is not None:
            existing.owner_name = owner_name
        await db.commit()
        await db.refresh(existing)
        return existing

    device = Device(
        organization_id=organization_id,
        name=name,
        mac=mac_norm,
        device_type=device_type,
        last_ip=last_ip,
        hostname=hostname,
        owner_name=owner_name,
        discovered=False,
    )
    db.add(device)
    await db.commit()
    await db.refresh(device)
    return device


_UNSET = object()


async def update_device(
    db: AsyncSession,
    device: Device,
    *,
    name: str | None = None,
    device_type: str | None = None,
    status: str | None = None,
    tags: list[str] | None = None,
    owner_name: str | None | object = _UNSET,
) -> Device:
    if name is not None:
        device.name = name.strip()
        device.discovered = False
    if device_type is not None:
        device.device_type = device_type
    if status is not None:
        device.status = status
    if tags is not None:
        device.tags = [t.strip() for t in tags if t.strip()][:20]
    if owner_name is not _UNSET:
        device.owner_name = owner_name
    await db.commit()
    await db.refresh(device)
    return device


async def delete_device(db: AsyncSession, device: Device) -> None:
    """Futa device. Matukio/software/agent-link zinabaki (device_id -> NULL)."""
    await db.delete(device)
    await db.commit()


async def match_or_create_device(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    mac: str | None,
    ip: str | None,
) -> Device | None:
    """Tafuta device kwa MAC, kisha kwa IP. Kama MAC ipo lakini haipo kwenye
    database, iunde (discovery). IP pekee HAIundi device, kwa sababu IP
    hubadilika, tunairejesha tu kama tayari inajulikana.
    """
    mac_norm = normalize_mac(mac)
    if mac_norm:
        device = (
            await db.execute(
                select(Device).where(
                    Device.organization_id == organization_id, Device.mac == mac_norm
                )
            )
        ).scalar_one_or_none()
        if device is None:
            device = Device(
                organization_id=organization_id,
                name=ip or mac_norm,
                mac=mac_norm,
                last_ip=ip,
                discovered=True,
            )
            db.add(device)
            await db.flush()
        return device

    if ip:
        return (
            await db.execute(
                select(Device).where(
                    Device.organization_id == organization_id, Device.last_ip == ip
                )
            )
        ).scalar_one_or_none()
    return None


async def upsert_discovered_device(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    mac: str | None,
    ip: str | None,
    hostname: str | None,
) -> Device | None:
    """Weka/rekebisha device kutoka discovery sweep. Inaunda kifaa kipya tu kama
    MAC inajulikana (kama match_or_create_device), kisha inasasisha hostname/IP.
    """
    device = await match_or_create_device(db, organization_id, mac=mac, ip=ip)
    if device is None:
        return None
    if ip:
        device.last_ip = ip
    if hostname and not device.hostname:
        device.hostname = hostname[:255]
    device.last_seen_at = datetime.now(timezone.utc)
    return device


def touch_device(device: Device, *, ip: str | None, when: datetime, flagged: bool) -> None:
    """Sasisha device baada ya tukio. Haifanyi commit, mwitaji ndiye ana-commit."""
    if ip:
        device.last_ip = ip
    device.last_seen_at = when
    device.events_count = (device.events_count or 0) + 1
    if flagged:
        device.risk_score = min(100, (device.risk_score or 0) + 10)


# --- Matukio --------------------------------------------------------------


async def list_events(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    limit: int = 100,
    offset: int = 0,
    only_flagged: bool = False,
    kind: str | None = None,
) -> tuple[list[tuple[SecurityEvent, str | None]], int]:
    """Inarudisha ((event, device_name), ...) na jumla."""
    where = [SecurityEvent.organization_id == organization_id]
    if only_flagged:
        where.append(SecurityEvent.verdict.in_(("malicious", "suspicious")))
    if kind:
        where.append(SecurityEvent.kind == kind)

    total = await db.scalar(select(func.count(SecurityEvent.id)).where(*where))
    stmt = (
        select(SecurityEvent, Device.name)
        .outerjoin(Device, SecurityEvent.device_id == Device.id)
        .where(*where)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = [(ev, name) for ev, name in (await db.execute(stmt)).all()]
    return rows, int(total or 0)


async def search(
    db: AsyncSession, organization_id: uuid.UUID, query: str, *, limit: int = 60
) -> tuple[list[tuple[SecurityEvent, str | None]], list[Device]]:
    """Tafuta kwenye events (domain/IP) na devices (jina/MAC/IP)."""
    like = f"%{query.strip()}%"
    ev_stmt = (
        select(SecurityEvent, Device.name)
        .outerjoin(Device, SecurityEvent.device_id == Device.id)
        .where(
            SecurityEvent.organization_id == organization_id,
            (SecurityEvent.domain.ilike(like))
            | (SecurityEvent.dst_ip.ilike(like))
            | (SecurityEvent.src_ip.ilike(like)),
        )
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    )
    events = [(ev, name) for ev, name in (await db.execute(ev_stmt)).all()]

    dev_stmt = (
        select(Device)
        .where(
            Device.organization_id == organization_id,
            (Device.name.ilike(like)) | (Device.mac.ilike(like)) | (Device.last_ip.ilike(like)),
        )
        .limit(20)
    )
    devices = list((await db.execute(dev_stmt)).scalars())
    return events, devices


_FIELD_COLUMNS: dict[str, object] = {
    "domain": SecurityEvent.domain,
    "ip": SecurityEvent.dst_ip,
    "src_ip": SecurityEvent.src_ip,
    "dst_ip": SecurityEvent.dst_ip,
    "dst_port": SecurityEvent.dst_port,
    "protocol": SecurityEvent.protocol,
    "kind": SecurityEvent.kind,
    "event_type": SecurityEvent.event_type,
    "verdict": SecurityEvent.verdict,
    "severity": SecurityEvent.severity,
    "country": SecurityEvent.country,
    "asn": SecurityEvent.asn,
    "device": Device.name,
    "account": SecurityEvent.account,
    "process_name": SecurityEvent.process_name,
    "file_path": SecurityEvent.file_path,
    "source": SecurityEvent.source,
}


async def siem_search(
    db: AsyncSession,
    organization_id: uuid.UUID,
    parsed,
    *,
    limit: int = 60,
) -> tuple[list[tuple[SecurityEvent, str | None]], list[Device], dict, float]:
    """Tafuta kwa kutumia query language (angalia `app/core/querylang.py`).

    Inarudisha (events, devices, breakdown, took_ms)."""
    import time

    from sqlalchemy import and_, not_, or_

    start = time.perf_counter()
    where: list = [SecurityEvent.organization_id == organization_id]
    dev_where: list = [Device.organization_id == organization_id]

    # --- vigezo vya fields ---
    for key, values in parsed.fields.items():
        col = _FIELD_COLUMNS.get(key)
        if col is None:
            continue
        for value, negated in values:
            clause = _value_clause(col, value)
            if clause is not None:
                where.append(not_(clause) if negated else clause)

    # --- wakati ---
    if parsed.after is not None:
        since_ts = datetime.fromtimestamp(parsed.after, tz=timezone.utc)
        where.append(SecurityEvent.occurred_at >= since_ts)
    if parsed.before is not None:
        until_ts = datetime.fromtimestamp(parsed.before, tz=timezone.utc)
        where.append(SecurityEvent.occurred_at <= until_ts)

    # --- has: key za raw JSONB ---
    for key in parsed.has:
        where.append(func.jsonb_exists(SecurityEvent.raw, key))

    # --- maneno huru: angani events + devices ---
    free_clauses: list = []
    for token in parsed.free:
        like = f"%{token}%"
        ev_clause = (
            SecurityEvent.domain.ilike(like)
            | SecurityEvent.dst_ip.ilike(like)
            | SecurityEvent.src_ip.ilike(like)
            | SecurityEvent.account.ilike(like)
            | SecurityEvent.process_name.ilike(like)
            | SecurityEvent.file_path.ilike(like)
            | SecurityEvent.source.ilike(like)
            | Device.name.ilike(like)
        )
        free_clauses.append(ev_clause)
        dev_where.append(
            or_(
                Device.name.ilike(like),
                Device.mac.ilike(like),
                Device.last_ip.ilike(like),
                Device.hostname.ilike(like),
            )
        )
    if free_clauses:
        where.append(and_(*free_clauses))

    # Breakdown ya severity kwa matokeo (kwa chart ya matokeo).
    breakdown = dict(
        (
            await db.execute(
                select(SecurityEvent.severity, func.count(SecurityEvent.id))
                .where(*where)
                .group_by(SecurityEvent.severity)
            )
        ).all()
    )

    stmt = (
        select(SecurityEvent, Device.name)
        .outerjoin(Device, SecurityEvent.device_id == Device.id)
        .where(*where)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    )
    events = [(ev, name) for ev, name in (await db.execute(stmt)).all()]

    if parsed.is_empty:
        dev_where = [Device.organization_id == organization_id]
    dev_stmt = select(Device).where(and_(*dev_where)).limit(20)
    devices = list((await db.execute(dev_stmt)).scalars())

    took = (time.perf_counter() - start) * 1000.0
    return events, devices, breakdown, took


def _value_clause(col, value: str):
    """Andika clause ya filter kwa col/col integer, kulingana na aina ya thamani."""
    if isinstance(col.type, Integer):
        try:
            return col == int(value)
        except ValueError:
            return None
    if value == "*":
        return col.isnot(None)
    return col.ilike(f"%{value}%")


# --- Sensor tokens --------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_sensor_token(
    db: AsyncSession, organization_id: uuid.UUID, label: str
) -> tuple[SensorToken, str]:
    """Inarudisha (row, token halisi). Token halisi haihifadhiwi popote."""
    plaintext = "hs_" + secrets.token_urlsafe(32)
    row = SensorToken(
        organization_id=organization_id,
        label=label.strip(),
        token_hash=_hash_token(plaintext),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row, plaintext


async def list_sensor_tokens(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[SensorToken]:
    stmt = (
        select(SensorToken)
        .where(SensorToken.organization_id == organization_id)
        .order_by(SensorToken.created_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def org_id_for_sensor_token(db: AsyncSession, token: str) -> uuid.UUID | None:
    """Thibitisha token ya sensor, sasisha `last_used_at`, rudisha org id."""
    stmt = select(SensorToken).where(
        SensorToken.token_hash == _hash_token(token),
        SensorToken.revoked_at.is_(None),
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None
    row.last_used_at = datetime.now(timezone.utc)
    await db.commit()
    return row.organization_id
