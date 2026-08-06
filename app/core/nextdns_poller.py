"""Poller ya NextDNS (multi-tenant).

Kila kipindi, inazunguka org ZOTE zenye NextDNS config iliyowashwa, inavuta DNS
query logs kutoka NextDNS API, na kuziingiza kwa org husika kupitia
`ingest_security_events` (enrichment ileile ya GeoIP/OTX + rules + arifa).

Hakuna bridge ya kuendesha wala token — mtumiaji anaweka NextDNS API key +
Profile ID mara moja kwenye HomeSIEM, backend inashughulikia mengine.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.core.ingest import ingest_security_events
from app.core.logging import get_logger
from app.crud import nextdns as crud
from app.db.session import AsyncSessionLocal

logger = get_logger(__name__)

_NEXTDNS_BASE = "https://api.nextdns.io"
_POLL_SECONDS = 20
_LOG_LIMIT = 100
#: api.nextdns.io iko nyuma ya Cloudflare inayozuia User-Agent za "bot" (error
#: 1010). LAZIMA tutume browser UA ndipo tuweze kufikia API.
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
_HEADERS_BASE = {"User-Agent": _UA, "Accept": "application/json"}


@dataclass
class _DnsEvent:
    domain: str | None
    src_ip: str | None
    ts: float
    kind: str = "dns"
    src_mac: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _sync_one(db, cfg, http: httpx.AsyncClient) -> None:
    try:
        r = await http.get(
            f"{_NEXTDNS_BASE}/profiles/{cfg.profile_id}/logs?limit={_LOG_LIMIT}",
            headers={"X-Api-Key": cfg.api_key, **_HEADERS_BASE},
        )
    except httpx.HTTPError as exc:
        await crud.mark_synced(db, cfg, status=f"fetch error: {exc}")
        return
    if r.status_code == 429:
        await crud.mark_synced(db, cfg, status="rate limited (will retry)")
        return
    if r.status_code >= 400:
        await crud.mark_synced(db, cfg, status=f"HTTP {r.status_code}: {r.text[:80]}")
        return

    data = r.json().get("data") if isinstance(r.json(), dict) else None
    rows = data if isinstance(data, list) else []

    last = cfg.last_event_at
    new_max = last
    events: list[_DnsEvent] = []
    for entry in rows:
        dt = _parse(entry.get("timestamp"))
        if dt is None:
            continue
        if last is not None and dt <= last:
            continue
        domain = (entry.get("domain") or "").strip()
        if not domain:
            continue
        events.append(_DnsEvent(domain=domain, src_ip=entry.get("clientIp") or None, ts=dt.timestamp()))
        if new_max is None or dt > new_max:
            new_max = dt

    if events:
        # newest-first kutoka NextDNS; hifadhi kwa mpangilio wa muda.
        events.reverse()
        await ingest_security_events(db, cfg.organization_id, events)
    await crud.mark_synced(db, cfg, status=f"ok ({len(events)} new)", last_event_at=new_max)


async def _tick() -> None:
    async with AsyncSessionLocal() as db:
        configs = await crud.all_enabled(db)
        if not configs:
            return
        async with httpx.AsyncClient(timeout=20) as http:
            for i, cfg in enumerate(configs):
                try:
                    await _sync_one(db, cfg, http)
                except Exception as exc:  # noqa: BLE001
                    logger.error("NextDNS sync imeshindwa (org=%s): %s", cfg.organization_id, exc)
                    await db.rollback()
                # Pacing: NextDNS ina-rate-limit maombi ya haraka (429).
                if i + 1 < len(configs):
                    await asyncio.sleep(0.5)


async def run_nextdns_poller(stop: asyncio.Event) -> None:
    logger.info("NextDNS poller imeanza (kila %ss)", _POLL_SECONDS)
    while not stop.is_set():
        try:
            await _tick()
        except Exception as exc:  # noqa: BLE001
            logger.error("NextDNS poller tick error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_POLL_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("NextDNS poller imesimama")
