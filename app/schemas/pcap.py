"""Schemas za uchambuzi wa pcap (upload → tshark → enrichment)."""

from __future__ import annotations

from pydantic import Field

from app.schemas.common import CamelModel
from app.schemas.intel import GeoLocation, Verdict


class DnsQuery(CamelModel):
    """Swali moja la DNS. Hili ndilo linaloonyesha 'kifaa X kilitaka kufungua Y'."""

    time: float | None = None
    src: str
    domain: str
    qtype: str
    #: Hukumu ya domain baada ya OTX (ikiwa ime-enrich-iwa).
    verdict: Verdict | None = None
    pulse_count: int = 0


class Flow(CamelModel):
    """Mkusanyiko wa packets kati ya src na dst (destination moja)."""

    src: str
    dst: str
    dst_port: int | None = None
    protocol: str
    packets: int
    bytes: int
    geo: GeoLocation | None = None
    verdict: Verdict | None = None
    pulse_count: int = 0


class PcapFinding(CamelModel):
    """Tukio lililotambuliwa, kwa ajili ya jedwali la 'Findings'."""

    title: str
    severity: Verdict
    detail: str
    indicator: str | None = None


class PcapAnalysis(CamelModel):
    file_name: str
    #: Idadi ya packets zilizosomwa (inaweza kuwa imekatwa na kikomo).
    packets_read: int
    truncated: bool = False
    duration_seconds: float | None = None
    dns_queries: list[DnsQuery] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    findings: list[PcapFinding] = Field(default_factory=list)
    #: Idadi ya vitu vya kipekee, kwa stat cards.
    unique_domains: int = 0
    unique_external_ips: int = 0
