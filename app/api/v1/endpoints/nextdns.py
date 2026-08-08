"""NextDNS integration (reseller model).

Single NextDNS API key (from settings) creates a profile per org.
Org clicks "Get DNS Network Configuration" -> we create the profile -> return
the DoH hostname (`{profile}.dns.nextdns.io`) + QR setup links.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import httpx
from fastapi import APIRouter, HTTPException, Response

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.config import settings
from app.core.logging import get_logger
from app.crud import nextdns as crud
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(prefix="/nextdns", tags=["nextdns"])

_ND_BASE = "https://api.nextdns.io"
_NS = uuid.UUID("5f2b9a10-1c3d-4e6f-8a90-abcdef012345")
#: Muda wa kuhifadhi logs (sekunde): siku 90.
_RETENTION_SECONDS = 7776000


class NextDnsRead(CamelModel):
    configured: bool
    profile_id: str | None = None
    profile_name: str | None = None
    doh_hostname: str | None = None
    enabled: bool = False
    last_synced_at: datetime | None = None
    last_status: str | None = None
    organization_id: str | None = None


def _headers() -> dict[str, str]:
    return {"X-Api-Key": settings.nextdns_api_key or "", "Content-Type": "application/json"}


def _read(cfg) -> NextDnsRead:
    if cfg is None:
        return NextDnsRead(configured=False)
    return NextDnsRead(
        configured=True,
        profile_id=cfg.profile_id,
        profile_name=cfg.profile_name,
        doh_hostname=cfg.doh_hostname,
        enabled=cfg.enabled,
        last_synced_at=cfg.last_synced_at,
        last_status=cfg.last_status,
        organization_id=str(cfg.organization_id) if cfg.organization_id else None,
    )


@router.get("", response_model=NextDnsRead, summary="Get this workspace's NextDNS config")
async def get_config(user: CurrentUser, db: DbSession) -> NextDnsRead:
    return _read(await crud.get_for_org(db, user.organization_id))


@router.post("/provision", response_model=NextDnsRead, summary="Create NextDNS profile for this org (owner)")
async def provision_profile(user: RequireOwner, db: DbSession) -> NextDnsRead:
    """Create a NextDNS profile for this org, enable its logs, and return the
    DoH hostname + setup link. The user never sees the NextDNS API key."""
    if not settings.nextdns_ready:
        raise HTTPException(status_code=503, detail="NextDNS not configured on server")

    cfg = await crud.get_for_org(db, user.organization_id)
    if cfg is not None and cfg.profile_id:
        return _read(cfg)

    profile_name = f"HomeSIEM {user.organization_id.hex[:12]}"
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.post(
                f"{_ND_BASE}/profiles",
                headers=_headers(),
                json={"name": profile_name},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"NextDNS API error: {exc}")

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"NextDNS API error: {r.text[:200]}")

    data = r.json()
    if data.get("errors"):
        raise HTTPException(
            status_code=502,
            detail=f"NextDNS API error: {data['errors'][0].get('detail', 'Unknown')}",
        )

    profile_id = (data.get("data") or {}).get("id")
    if not profile_id:
        raise HTTPException(status_code=502, detail="NextDNS did not return a profile ID")

    # Enable + retain logs (best-effort: provisioning should still succeed if this fails).
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            p = await http.patch(
                f"{_ND_BASE}/profiles/{profile_id}/settings/logs",
                headers=_headers(),
                json={"enabled": True, "retention": _RETENTION_SECONDS},
            )
        if p.status_code >= 400:
            logger.warning("Could not enable NextDNS logs (profile=%s): %s", profile_id, p.text[:120])
    except httpx.HTTPError as exc:
        logger.warning("NextDNS logs enable imeshindwa (profile=%s): %s", profile_id, exc)

    cfg = await crud.upsert(db, user.organization_id, profile_id=profile_id, profile_name=profile_name)
    logger.info("NextDNS profile created (org=%s, profile=%s)", user.organization_id, profile_id)
    return _read(cfg)


@router.delete("", response_model=Message, summary="Disconnect NextDNS (owner)")
async def delete_config(user: RequireOwner, db: DbSession) -> Message:
    cfg = await crud.get_for_org(db, user.organization_id)
    profile_id = cfg.profile_id if cfg else None
    await crud.delete_for_org(db, user.organization_id)

    if profile_id and settings.nextdns_ready:
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                await http.delete(f"{_ND_BASE}/profiles/{profile_id}", headers=_headers())
        except httpx.HTTPError as exc:
            logger.warning("NextDNS profile delete imeshindwa (profile=%s): %s", profile_id, exc)

    return Message(detail="NextDNS disconnected.", code="nextdns_deleted")


def _mobileconfig(doh_url: str, org_id: uuid.UUID) -> str:
    """iOS DNS-over-HTTPS configuration profile kwa DoH endpoint ya org hii."""
    u1 = uuid.uuid5(_NS, f"dns:{org_id}")
    u2 = uuid.uuid5(_NS, f"cfg:{org_id}")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>'
        "<key>PayloadContent</key><array><dict>"
        "<key>DNSSettings</key><dict>"
        "<key>DNSProtocol</key><string>HTTPS</string>"
        f"<key>ServerURL</key><string>{doh_url}</string>"
        "</dict>"
        "<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>"
        f"<key>PayloadIdentifier</key><string>io.homesiem.dns.{org_id.hex[:16]}</string>"
        f"<key>PayloadUUID</key><string>{u1}</string>"
        "<key>PayloadDisplayName</key><string>HomeSIEM DNS</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "</dict></array>"
        "<key>PayloadDisplayName</key><string>HomeSIEM Network Monitoring</string>"
        f"<key>PayloadIdentifier</key><string>io.homesiem.{org_id.hex[:16]}</string>"
        "<key>PayloadType</key><string>Configuration</string>"
        f"<key>PayloadUUID</key><string>{u2}</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "<key>PayloadDescription</key><string>Routes this device's DNS through HomeSIEM so you can see what it connects to.</string>"
        "</dict></plist>"
    )


@router.get("/apple/{org_id}", summary="iOS DNS config profile (public, scan-to-install)")
async def apple_profile(org_id: str, db: DbSession) -> Response:
    """Bila auth kwa makusudi: simu (Safari) inaipakua kwa QR bila kuingia."""
    try:
        org_uuid = uuid.UUID(org_id)
    except ValueError:
        return Response(status_code=404)

    cfg = await crud.get_for_org(db, org_uuid)
    if not cfg or not cfg.profile_id:
        return Response(status_code=404)

    doh_url = f"https://dns.nextdns.io/{cfg.profile_id}"
    return Response(
        content=_mobileconfig(doh_url, org_uuid),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="homesiem-dns.mobileconfig"'},
    )
