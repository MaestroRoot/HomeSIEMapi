"""Schemas za threat intel na enrichment (OTX + GeoIP)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.schemas.common import CamelModel

#: Aina za indicator tunazotambua.
IndicatorType = Literal["ip", "domain", "url", "sha256", "md5", "sha1"]

#: Hukumu ya mwisho. `unknown` ni tofauti na `clean`: OTX haijui tu, sio
#: kwamba imethibitisha ni salama.
Verdict = Literal["malicious", "suspicious", "clean", "unknown"]


class GeoLocation(CamelModel):
    ip: str
    is_private: bool = False
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_org: str | None = None


class IntelResult(CamelModel):
    """Matokeo ya lookup ya indicator mmoja."""

    indicator: str
    type: IndicatorType
    verdict: Verdict
    #: Idadi ya OTX pulses zinazogusa indicator hii.
    pulse_count: int = 0
    #: Tags kutoka kwenye pulses, zilizounganishwa na kupunguzwa marudio.
    tags: list[str] = Field(default_factory=list)
    #: Tarehe ya pulse ya zamani zaidi (ISO), inakadiria "first seen".
    first_seen: str | None = None
    #: Eneo la IP, kwa indicators za aina ya `ip` pekee.
    geo: GeoLocation | None = None
    #: Maelezo mafupi ya jinsi hukumu ilivyofikiwa (heuristic, si ukweli kamili).
    rationale: str | None = None
