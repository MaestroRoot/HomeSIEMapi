"""Poller ya NextDNS (multi-tenant, reseller model).

Kila kipindi, inazunguka org ZOTE zenye NextDNS config iliyowashwa, inavuta DNS
query logs kutoka NextDNS API (single key), na kuziingiza kwa org husika kupitia
`ingest_security_events` (enrichment ileile ya GeoIP/OTX + rules + arifa).

Reseller model: single NextDNS API key (from settings), profile per org.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.core.config import settings
from app.core.ingest import ingest_security_events
from app.core.logging import get_logger
from app.crud import nextdns as crud
from app.db.session import AsyncSessionLocal

logger = get_logger(__name__)

_ND_BASE = "https://api.nextdns.io"
_POLL_SECONDS = 30
_LOG_LIMIT = 1000
_MAX_PAGES = 4
_UA = "HomeSIEM/1.0 (backend dns poller)"


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
    event_type: str = "dns"
    source: str = "nextdns"


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def _first_run_from() -> str:
    """Relative date inayokubalika na NextDNS kwa mara ya kwanza (backlog ndogo)."""
    return "-24h"


async def _fetch_logs(
    http: httpx.AsyncClient, profile_id: str, since: datetime | None
) -> tuple[list[dict], datetime | None]:
    """Vuta logs za profile hadi kikomo cha kurasa; rudisha (entries, newest_ts)."""
    headers = {"X-Api-Key": settings.nextdns_api_key or "", "User-Agent": _UA}
    params: dict = {
        "limit": _LOG_LIMIT,
        "sort": "asc",
        "raw": "0",
    }
    if since is not None:
        params["from"] = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    else:
        params["from"] = _first_run_from()

    entries: list[dict] = []
    newest: datetime | None = None

    for _ in range(_MAX_PAGES):
        r = await http.get(f"{_ND_BASE}/profiles/{profile_id}/logs", headers=headers, params=params)
        if r.status_code == 429:
            raise _RateLimited()
        if r.status_code >= 400:
            raise _ApiError(f"HTTP {r.status_code}: {r.text[:120]}")

        data = r.json()
        batch = data.get("data") or []
        if not isinstance(batch, list):
            batch = []
        for entry in batch:
            dt = _parse(entry.get("timestamp"))
            if dt is None:
                continue
            if newest is None or dt > newest:
                newest = dt
        entries.extend(batch)

        cursor = (data.get("meta") or {}).get("pagination", {}).get("cursor")
        if not cursor:
            break
        params["cursor"] = cursor

    return entries, newest


class _RateLimited(Exception):
    pass


class _ApiError(Exception):
    pass


async def _sync_one(db, cfg, http: httpx.AsyncClient) -> None:
    if not cfg.profile_id:
        await crud.mark_synced(db, cfg, status="no profile_id (not provisioned)")
        return

    since = cfg.last_event_at
    try:
        entries, newest = await _fetch_logs(http, cfg.profile_id, since)
    except _RateLimited:
        await crud.mark_synced(db, cfg, status="rate limited (will retry)")
        return
    except (_ApiError, httpx.HTTPError) as exc:
        await crud.mark_synced(db, cfg, status=f"logs fetch error: {exc}")
        return

    last = cfg.last_event_at
    events: list[_DnsEvent] = []
    for entry in entries:
        dt = _parse(entry.get("timestamp"))
        if dt is None:
            continue
        if last is not None and dt <= last:
            continue
        domain = (entry.get("domain") or "").strip()
        if not domain:
            continue
        if domain.endswith("."):
            domain = domain[:-1]
        src_ip = entry.get("clientIp")
        events.append(_DnsEvent(domain=domain, src_ip=src_ip, ts=dt.timestamp()))

    if events:
        await ingest_security_events(db, cfg.organization_id, events)
    await crud.mark_synced(db, cfg, status=f"ok ({len(events)} new)", last_event_at=newest)


async def _tick() -> None:
    if not settings.nextdns_ready:
        logger.warning("NextDNS poller skipped: API key not configured")
        return

    async with AsyncSessionLocal() as db:
        configs = await crud.all_enabled(db)
        if not configs:
            return
        async with httpx.AsyncClient(timeout=30) as http:
            for i, cfg in enumerate(configs):
                try:
                    await _sync_one(db, cfg, http)
                except Exception as exc:  # noqa: BLE001
                    logger.error("NextDNS sync imeshindwa (org=%s): %s", cfg.organization_id, exc)
                    await db.rollback()
                # Pacing
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
