"""Poller ya Cloudflare Gateway (multi-tenant, reseller model).

Kila kipindi, inazunguka org ZOTE zenye Cloudflare Gateway config iliyowashwa, inavuta DNS
query logs kutoka Cloudflare Zero Trust API (single account), na kuziingiza kwa org husika
kupitia `ingest_security_events` (enrichment ileile ya GeoIP/OTX + rules + arifa).

Reseller model: single Cloudflare account (from settings), location per org.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.core.config import settings
from app.core.ingest import ingest_security_events
from app.core.logging import get_logger
from app.crud import cloudflare_gateway as crud
from app.db.session import AsyncSessionLocal

logger = get_logger(__name__)

_CF_BASE = "https://api.cloudflare.com/client/v4"
_POLL_SECONDS = 30
_LOG_LIMIT = 500
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
    if not cfg.location_id:
        await crud.mark_synced(db, cfg, status="no location_id (not provisioned)")
        return

    headers = {"Authorization": f"Bearer {settings.cloudflare_api_token}", **_HEADERS_BASE}

    # Fetch DNS logs for this location
    try:
        r = await http.get(
            f"{_CF_BASE}/accounts/{settings.cloudflare_account_id}/gateway/dns/logs",
            headers=headers,
            params={"location_id": cfg.location_id, "limit": _LOG_LIMIT, "order": "desc"},
        )
    except httpx.HTTPError as exc:
        await crud.mark_synced(db, cfg, status=f"logs fetch error: {exc}")
        return

    if r.status_code == 429:
        await crud.mark_synced(db, cfg, status="rate limited (will retry)")
        return
    if r.status_code >= 400:
        await crud.mark_synced(db, cfg, status=f"HTTP {r.status_code}: {r.text[:80]}")
        return

    data = r.json()
    if not data.get("success"):
        errors = data.get("errors", [{"message": "Unknown error"}])
        await crud.mark_synced(db, cfg, status=f"API error: {errors[0].get('message', 'Unknown')}")
        return

    rows = data.get("result", [])
    if not isinstance(rows, list):
        rows = []

    last = cfg.last_event_at
    new_max = last
    events: list[_DnsEvent] = []

    for entry in rows:
        dt = _parse(entry.get("timestamp"))
        if dt is None:
            continue
        if last is not None and dt <= last:
            continue
        domain = (entry.get("query", {}).get("name") or "").strip()
        if not domain:
            continue
        # Remove trailing dot from FQDN
        if domain.endswith("."):
            domain = domain[:-1]
        src_ip = entry.get("client_ip") or entry.get("src_ip")
        events.append(_DnsEvent(domain=domain, src_ip=src_ip, ts=dt.timestamp()))
        if new_max is None or dt > new_max:
            new_max = dt

    if events:
        events.reverse()  # oldest first
        await ingest_security_events(db, cfg.organization_id, events)
    await crud.mark_synced(db, cfg, status=f"ok ({len(events)} new)", last_event_at=new_max)


async def _tick() -> None:
    if not settings.cloudflare_gateway_ready:
        logger.warning("Cloudflare Gateway poller skipped: credentials not configured")
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
                    logger.error("Cloudflare Gateway sync imeshindwa (org=%s): %s", cfg.organization_id, exc)
                    await db.rollback()
                # Pacing
                if i + 1 < len(configs):
                    await asyncio.sleep(0.5)


async def run_cloudflare_gateway_poller(stop: asyncio.Event) -> None:
    logger.info("Cloudflare Gateway poller imeanza (kila %ss)", _POLL_SECONDS)
    while not stop.is_set():
        try:
            await _tick()
        except Exception as exc:  # noqa: BLE001
            logger.error("Cloudflare Gateway poller tick error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_POLL_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("Cloudflare Gateway poller imesimama")