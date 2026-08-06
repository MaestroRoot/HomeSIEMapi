"""NextDNS integration (per-org). Mtumiaji anaweka Profile ID + API Key mara
moja; backend poller inavuta DNS logs na kuziingiza. Hakuna bridge/token."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Response
from pydantic import Field

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.logging import get_logger
from app.crud import nextdns as crud
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(prefix="/nextdns", tags=["nextdns"])


class NextDnsRead(CamelModel):
    configured: bool
    profile_id: str | None = None
    #: API key imefichwa (mfano "••••50cf") — raw haitolewi kamwe.
    api_key_masked: str | None = None
    enabled: bool = False
    #: Hostname ya kuweka kwenye Private DNS ya simu.
    dns_hostname: str | None = None
    last_synced_at: datetime | None = None
    last_status: str | None = None


class NextDnsWrite(CamelModel):
    profile_id: str = Field(min_length=4, max_length=32)
    api_key: str = Field(min_length=8, max_length=128)


def _read(cfg) -> NextDnsRead:
    if cfg is None:
        return NextDnsRead(configured=False)
    key = cfg.api_key or ""
    masked = ("•" * 4 + key[-4:]) if len(key) >= 4 else "••••"
    return NextDnsRead(
        configured=True,
        profile_id=cfg.profile_id,
        api_key_masked=masked,
        enabled=cfg.enabled,
        dns_hostname=f"{cfg.profile_id}.dns.nextdns.io",
        last_synced_at=cfg.last_synced_at,
        last_status=cfg.last_status,
    )


@router.get("", response_model=NextDnsRead, summary="Get this workspace's NextDNS config")
async def get_config(user: CurrentUser, db: DbSession) -> NextDnsRead:
    return _read(await crud.get_for_org(db, user.organization_id))


@router.put("", response_model=NextDnsRead, summary="Set NextDNS profile + API key (owner)")
async def set_config(payload: NextDnsWrite, user: RequireOwner, db: DbSession) -> NextDnsRead:
    cfg = await crud.upsert(
        db, user.organization_id, profile_id=payload.profile_id, api_key=payload.api_key
    )
    logger.info("NextDNS config imewekwa (org=%s, profile=%s)", user.organization_id, cfg.profile_id)
    return _read(cfg)


@router.delete("", response_model=Message, summary="Disconnect NextDNS (owner)")
async def delete_config(user: RequireOwner, db: DbSession) -> Message:
    await crud.delete_for_org(db, user.organization_id)
    return Message(detail="NextDNS disconnected.", code="nextdns_deleted")


_NS = uuid.UUID("5f2b9a10-1c3d-4e6f-8a90-abcdef012345")


def _mobileconfig(profile_id: str) -> str:
    """iOS DNS-over-HTTPS configuration profile ya NextDNS profile husika.
    Mteja anai-install (mara moja) → simu inatumia DNS hii. UUID ni deterministic
    ili re-install ibadilishe ile ile badala ya kuongeza mpya."""
    u1 = uuid.uuid5(_NS, f"dns:{profile_id}")
    u2 = uuid.uuid5(_NS, f"cfg:{profile_id}")
    doh = f"https://dns.nextdns.io/{profile_id}"
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
        f"<key>PayloadIdentifier</key><string>io.homesiem.dns.{profile_id}</string>"
        f"<key>PayloadUUID</key><string>{u1}</string>"
        "<key>PayloadDisplayName</key><string>HomeSIEM DNS</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "</dict></array>"
        "<key>PayloadDisplayName</key><string>HomeSIEM Network Monitoring</string>"
        f"<key>PayloadIdentifier</key><string>io.homesiem.{profile_id}</string>"
        "<key>PayloadType</key><string>Configuration</string>"
        f"<key>PayloadUUID</key><string>{u2}</string>"
        "<key>PayloadVersion</key><integer>1</integer>"
        "<key>PayloadDescription</key><string>Routes this device's DNS through HomeSIEM so you can see what it connects to.</string>"
        "</dict></plist>"
    )


@router.get("/apple/{profile_id}", summary="iOS DNS config profile (public, scan-to-install)")
async def apple_profile(profile_id: str) -> Response:
    """Bila auth kwa makusudi: simu (Safari) inaipakua kwa QR bila kuingia. Ina
    DNS config tu (hakuna data nyeti). profile_id ni herufi/namba pekee."""
    pid = re.sub(r"[^a-zA-Z0-9]", "", profile_id)[:32]
    if not pid:
        return Response(status_code=404)
    return Response(
        content=_mobileconfig(pid),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="homesiem-dns.mobileconfig"'},
    )
