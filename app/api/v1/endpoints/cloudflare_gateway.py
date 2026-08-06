"""Cloudflare Gateway integration (reseller model).

Single Cloudflare account (from settings) creates locations per org.
Org clicks "Connect" → we create location → return DoH hostname.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

import httpx
from fastapi import APIRouter, HTTPException, Response
from pydantic import Field

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.config import settings
from app.core.logging import get_logger
from app.crud import cloudflare_gateway as crud
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(prefix="/cloudflare-gateway", tags=["cloudflare-gateway"])

_CF_BASE = "https://api.cloudflare.com/client/v4"
_NS = uuid.UUID("5f2b9a10-1c3d-4e6f-8a90-abcdef012345")


class CloudflareGatewayRead(CamelModel):
    configured: bool
    location_id: str | None = None
    location_name: str | None = None
    doh_hostname: str | None = None
    enabled: bool = False
    last_synced_at: datetime | None = None
    last_status: str | None = None
    organization_id: str | None = None


def _read(cfg) -> CloudflareGatewayRead:
    if cfg is None:
        return CloudflareGatewayRead(configured=False)
    return CloudflareGatewayRead(
        configured=True,
        location_id=cfg.location_id,
        location_name=cfg.location_name,
        doh_hostname=cfg.doh_hostname,
        enabled=cfg.enabled,
        last_synced_at=cfg.last_synced_at,
        last_status=cfg.last_status,
        organization_id=str(cfg.organization_id) if cfg.organization_id else None,
    )


@router.get("", response_model=CloudflareGatewayRead, summary="Get this workspace's Cloudflare Gateway config")
async def get_config(user: CurrentUser, db: DbSession) -> CloudflareGatewayRead:
    return _read(await crud.get_for_org(db, user.organization_id))


@router.post("/provision", response_model=CloudflareGatewayRead, summary="Create Cloudflare Gateway location for this org (owner)")
async def provision_location(user: RequireOwner, db: DbSession) -> CloudflareGatewayRead:
    """Create a Gateway location in Cloudflare for this org and save config."""
    if not settings.cloudflare_gateway_ready:
        raise HTTPException(status_code=503, detail="Cloudflare Gateway not configured on server")

    # Ensure config exists
    cfg = await crud.upsert(db, user.organization_id)
    if cfg.location_id:
        # Already provisioned
        return _read(cfg)

    # Create location in Cloudflare
    location_name = f"home-{user.organization_id.hex[:12]}"
    headers = {"Authorization": f"Bearer {settings.cloudflare_api_token}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.post(
                f"{_CF_BASE}/accounts/{settings.cloudflare_account_id}/gateway/locations",
                headers=headers,
                json={"name": location_name},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {exc}")

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {r.text[:200]}")

    data = r.json()
    if not data.get("success"):
        errors = data.get("errors", [{"message": "Unknown error"}])
        raise HTTPException(status_code=502, detail=f"Cloudflare API error: {errors[0].get('message', 'Unknown')}")

    location = data.get("result", {})
    location_id = location.get("id")
    location_name = location.get("name", location_name)

    if not location_id:
        raise HTTPException(status_code=502, detail="Cloudflare did not return location ID")

    # Update config with location info
    await crud.mark_synced(
        db, cfg, status="provisioned",
        location_id=location_id, location_name=location_name
    )
    await db.refresh(cfg)

    logger.info("Cloudflare Gateway location created (org=%s, location=%s)", user.organization_id, location_id)
    return _read(cfg)


@router.delete("", response_model=Message, summary="Disconnect Cloudflare Gateway (owner)")
async def delete_config(user: RequireOwner, db: DbSession) -> Message:
    await crud.delete_for_org(db, user.organization_id)
    return Message(detail="Cloudflare Gateway disconnected.", code="cloudflare_gateway_deleted")


def _mobileconfig(doh_url: str, org_id: uuid.UUID) -> str:
    """iOS DNS-over-HTTPS configuration profile for this org's DoH endpoint."""
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
    if not cfg or not cfg.doh_hostname:
        return Response(status_code=404)

    doh_url = f"https://{cfg.doh_hostname}/dns-query"
    return Response(
        content=_mobileconfig(doh_url, org_uuid),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="homesiem-dns.mobileconfig"'},
    )