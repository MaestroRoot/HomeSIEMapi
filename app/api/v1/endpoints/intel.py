"""Threat intel lookup: OTX + GeoIP kwa indicator moja.

Inatumiwa na IocScanner upande wa frontend. GeoIP inaongezwa hapa (si ndani ya
`threatintel.py`) ili kila module ibaki na jukumu moja: OTX inajua reputation,
GeoIP inajua eneo, endpoint inaziunganisha.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.core import geoip, threatintel
from app.core.config import settings
from app.core.logging import get_logger
from app.crud import stats as stats_crud
from app.schemas.common import CamelModel
from app.schemas.intel import IntelResult

logger = get_logger(__name__)

router = APIRouter(prefix="/intel", tags=["intel"])


class Feed(CamelModel):
    name: str
    type: str
    status: str
    detail: str


class FeedsResponse(CamelModel):
    feeds: list[Feed]
    flagged_seen: int


@router.get("/feeds", response_model=FeedsResponse, summary="Threat intel feed status")
async def feeds(user: CurrentUser, db: DbSession) -> FeedsResponse:
    stats = await stats_crud.overview(db, user.organization_id)
    feeds = [
        Feed(
            name="AlienVault OTX",
            type="Reputation (IP/domain/URL/hash)",
            status="active" if settings.otx_enabled else "not configured",
            detail="Community pulses. Verdicts: on allow-list -> clean, in pulses -> suspicious.",
        ),
        Feed(
            name="MaxMind GeoLite2",
            type="GeoIP (country + ASN)",
            status="active" if settings.geoip_enabled else "not configured",
            detail="Offline enrichment of every external IP with location and network owner.",
        ),
    ]
    flagged = stats.by_verdict.malicious + stats.by_verdict.suspicious
    return FeedsResponse(feeds=feeds, flagged_seen=flagged)


@router.get("/lookup", response_model=IntelResult, summary="Look up an indicator")
async def lookup_indicator(
    _user: CurrentUser,
    value: Annotated[str, Query(min_length=1, max_length=2048, description="IP, domain, URL or hash")],
) -> IntelResult:
    """Uliza OTX kuhusu indicator, na kwa IP ongeza eneo la GeoIP."""
    result = await threatintel.lookup(value)
    if result.type == "ip":
        result.geo = geoip.lookup(result.indicator)
    return result
