"""NextDNS integration (per-org). Mtumiaji anaweka Profile ID + API Key mara
moja; backend poller inavuta DNS logs na kuziingiza. Hakuna bridge/token."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
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
