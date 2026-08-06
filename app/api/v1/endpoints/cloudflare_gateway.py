"""Cloudflare Gateway integration (per-org). Mtumiaji anaweka Account ID + API Token mara
moja; backend poller inavuta DNS logs na kuziingiza. Hakuna bridge/token ya kuendesha."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Response
from pydantic import Field

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.logging import get_logger
from app.crud import cloudflare_gateway as crud
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(prefix="/cloudflare-gateway", tags=["cloudflare-gateway"])


class CloudflareGatewayRead(CamelModel):
    configured: bool
    account_id: str | None = None
    location_id: str | None = None
    location_name: str | None = None
    doh_hostname: str | None = None
    enabled: bool = False
    last_synced_at: datetime | None = None
    last_status: str | None = None


class CloudflareGatewayWrite(CamelModel):
    account_id: str = Field(min_length=8, max_length=64)
    api_token: str = Field(min_length=16, max_length=256)


def _read(cfg) -> CloudflareGatewayRead:
    if cfg is None:
        return CloudflareGatewayRead(configured=False)
    return CloudflareGatewayRead(
        configured=True,
        account_id=cfg.account_id,
        location_id=cfg.location_id,
        location_name=cfg.location_name,
        doh_hostname=f"{cfg.location_id}.dns.cloudflare-gateway.com" if cfg.location_id else None,
        enabled=cfg.enabled,
        last_synced_at=cfg.last_synced_at,
        last_status=cfg.last_status,
    )


@router.get("", response_model=CloudflareGatewayRead, summary="Get this workspace's Cloudflare Gateway config")
async def get_config(user: CurrentUser, db: DbSession) -> CloudflareGatewayRead:
    return _read(await crud.get_for_org(db, user.organization_id))


@router.put("", response_model=CloudflareGatewayRead, summary="Set Cloudflare Gateway account + API token (owner)")
async def set_config(payload: CloudflareGatewayWrite, user: RequireOwner, db: DbSession) -> CloudflareGatewayRead:
    cfg = await crud.upsert(
        db, user.organization_id, account_id=payload.account_id, api_token=payload.api_token
    )
    logger.info("Cloudflare Gateway config imewekwa (org=%s, account=%s)", user.organization_id, cfg.account_id)
    return _read(cfg)


@router.delete("", response_model=Message, summary="Disconnect Cloudflare Gateway (owner)")
async def delete_config(user: RequireOwner, db: DbSession) -> Message:
    await crud.delete_for_org(db, user.organization_id)
    return Message(detail="Cloudflare Gateway disconnected.", code="cloudflare_gateway_deleted")


_NS = uuid.UUID("5f2b9a10-1c3d-4e6f-8a90-abcdef012345")


def _mobileconfig(account_id: str, location_id: str) -> str:
    """iOS DNS-over-HTTPS configuration profile ya Cloudflare Gateway location husika.
    Mteja anai-install (mara moja) → simu inatumia DNS hii. UUID ni deterministic
    ili re-install ibadilishe ile ile badala ya kuongeza mpya."""
    u1 = uuid.uuid5(_NS, f"dns:{account_id}:{location_id}")
    u2 = uuid.uuid5(_NS, f"cfg:{account_id}:{location_id}")
    doh = f"https://{location_id}.dns.cloudflare-gateway.com/dns-query"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>'
        "<key>PayloadContent</key><array><dict>"
        "<key>DNSSettings</key><dict>"
        "<key>DNSProtocol</key><string>HTTPS</string>"
        f"<key>ServerURL</key><string>{doh}</string>"
        "</dict>"
        "<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>"
        f"<key>PayloadIdentifier</key><string>io.homesiem.dns.{account_id}.{location_id}</string>"
        f"<key>PayloadUUID</key><string>{u1}</string>"
        "<key>PayloadDisplayName</key><string>HomeSIEM DNS</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "</dict></array>"
        "<key>PayloadDisplayName</key><string>HomeSIEM Network Monitoring</string>"
        f"<key>PayloadIdentifier</key><string>io.homesiem.{account_id}.{location_id}</string>"
        "<key>PayloadType</key><string>Configuration</string>"
        f"<key>PayloadUUID</key><string>{u2}</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "<key>PayloadDescription</key><string>Routes this device's DNS through HomeSIEM so you can see what it connects to.</string>"
        "</dict></plist>"
    )


@router.get("/apple/{account_id}/{location_id}", summary="iOS DNS config profile (public, scan-to-install)")
async def apple_profile(account_id: str, location_id: str) -> Response:
    """Bila auth kwa makusudi: simu (Safari) inaipakua kwa QR bila kuingia. Ina
    DNS config tu (hakuna data nyeti). account_id na location_id ni herufi/namba pekee."""
    aid = re.sub(r"[^a-zA-Z0-9]", "", account_id)[:64]
    lid = re.sub(r"[^a-zA-Z0-9]", "", location_id)[:64]
    if not aid or not lid:
        return Response(status_code=404)
    return Response(
        content=_mobileconfig(aid, lid),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="homesiem-dns.mobileconfig"'},
    )