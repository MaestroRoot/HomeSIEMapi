"""Upload ya pcap → tshark → enrichment (GeoIP + OTX) → findings.

Hii ndiyo hatua ya kwanza inayothibitisha injini nzima kwenye traffic halisi
bila kuhitaji agent wala kugusa router: mtumiaji anakamata pcap nyumbani,
ana-upload, backend inatoa DNS + flows, ina-enrich, na inaonyesha ni domain/IP
gani ni hatari.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

from fastapi import APIRouter, UploadFile

from app.api.deps import CurrentUser
from app.core import geoip, pcap, pcap_parser, threatintel
from app.core.config import settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.schemas.pcap import DnsQuery, Flow, PcapAnalysis, PcapFinding

logger = get_logger(__name__)

router = APIRouter(prefix="/capture", tags=["capture"])

_ALLOWED_SUFFIXES = (".pcap", ".pcapng", ".cap")
#: Kiwango cha juu cha lookups za OTX kwa upload mmoja, kulinda rate limit.
#: Domains (ishara ya 'click') zinapewa kipaumbele kuliko IP.
_OTX_MAX_DOMAINS = 30
_OTX_MAX_IPS = 15
_OTX_CONCURRENCY = 5


async def _save_upload(file: UploadFile) -> str:
    """Hifadhi upload kwenye faili ya muda, ukisimamisha kikomo cha ukubwa."""
    name = (file.filename or "").lower()
    if not name.endswith(_ALLOWED_SUFFIXES):
        raise AppError(
            "Only .pcap, .pcapng and .cap capture files are supported.",
            code="pcap_bad_type",
        )

    fd, path = tempfile.mkstemp(suffix=".pcap")
    size = 0
    try:
        with os.fdopen(fd, "wb") as tmp:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.pcap_max_bytes:
                    raise AppError(
                        f"The capture is larger than the {settings.pcap_max_bytes // (1024 * 1024)} MB "
                        "limit for direct upload.",
                        code="pcap_too_large",
                    )
                tmp.write(chunk)
    except Exception:
        os.unlink(path)
        raise

    if size == 0:
        os.unlink(path)
        raise AppError("The uploaded file is empty.", code="pcap_empty")
    return path


async def _otx_safe(value: str, itype):
    """OTX lookup inayomeza makosa: enrichment ni ya ziada, isiangushe upload."""
    try:
        return await threatintel.lookup(value, itype)
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTX enrichment ya %s imeshindwa: %s", value, exc)
        return None


async def _enrich_with_otx(values: list[tuple[str, str]]) -> dict[str, tuple[str, int]]:
    """Uliza OTX kwa (value, type) nyingi kwa pamoja (semaphore).

    Inarudisha { value -> (verdict, pulse_count) }.
    """
    sem = asyncio.Semaphore(_OTX_CONCURRENCY)

    async def one(value: str, itype: str):
        async with sem:
            return value, await _otx_safe(value, itype)

    out: dict[str, tuple[str, int]] = {}
    for coro in asyncio.as_completed([one(v, t) for v, t in values]):
        value, result = await coro
        if result is not None:
            out[value] = (result.verdict, result.pulse_count)
    return out


def _build_findings(dns: list[DnsQuery], flows: list[Flow]) -> list[PcapFinding]:
    findings: list[PcapFinding] = []
    for q in dns:
        if q.verdict in ("malicious", "suspicious"):
            findings.append(
                PcapFinding(
                    title=f"{q.src} looked up a flagged domain",
                    severity=q.verdict,
                    detail=(
                        f"{q.src} resolved {q.domain}, which appears in "
                        f"{q.pulse_count} OTX threat report(s)."
                    ),
                    indicator=q.domain,
                )
            )
    for f in flows:
        if f.verdict in ("malicious", "suspicious"):
            where = ""
            if f.geo and (f.geo.country or f.geo.asn_org):
                where = f" ({', '.join(x for x in (f.geo.country, f.geo.asn_org) if x)})"
            findings.append(
                PcapFinding(
                    title=f"{f.src} contacted a flagged address",
                    severity=f.verdict,
                    detail=(
                        f"{f.src} exchanged {f.packets} packet(s) with {f.dst}{where}, "
                        f"seen in {f.pulse_count} OTX threat report(s)."
                    ),
                    indicator=f.dst,
                )
            )
    #: malicious kwanza.
    order = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
    findings.sort(key=lambda x: order.get(x.severity, 9))
    return findings


@router.post("/pcap", response_model=PcapAnalysis, summary="Analyse an uploaded capture")
async def analyse_pcap(_user: CurrentUser, file: UploadFile) -> PcapAnalysis:
    """Soma pcap, toa DNS + flows, enrich kwa GeoIP + OTX, rudisha findings."""
    path = await _save_upload(file)
    try:
        # Use tshark if available, otherwise fall back to pure-Python parser.
        if settings.tshark_available:
            (dns_queries), (flows, packets_read, duration) = await asyncio.gather(
                pcap.extract_dns(path),
                pcap.extract_flows(path),
            )
        else:
            logger.info("tshark not found, using pure-Python pcap parser")
            dns_queries, flows_result = await asyncio.gather(
                asyncio.to_thread(pcap_parser.extract_dns, path),
                asyncio.to_thread(pcap_parser.extract_flows, path),
            )
            flows, packets_read, duration = flows_result
    finally:
        os.unlink(path)

    # --- GeoIP: kwa kila IP ya nje (ni ya bure, hakuna rate limit) --------
    ext_ips = pcap.external_ips(flows)
    geo_by_ip = {ip: geoip.lookup(ip) for ip in ext_ips}
    for f in flows:
        f.geo = geo_by_ip.get(f.dst)

    # --- OTX: domains (kipaumbele) kisha IP za nje, kwa kikomo ------------
    if settings.otx_enabled:
        domains = list(dict.fromkeys(q.domain for q in dns_queries))[:_OTX_MAX_DOMAINS]
        ips = ext_ips[:_OTX_MAX_IPS]
        targets = [(d, "domain") for d in domains] + [(ip, "ip") for ip in ips]
        verdicts = await _enrich_with_otx(targets)

        for q in dns_queries:
            if q.domain in verdicts:
                q.verdict, q.pulse_count = verdicts[q.domain]
        for f in flows:
            if f.dst in verdicts:
                f.verdict, f.pulse_count = verdicts[f.dst]

    findings = _build_findings(dns_queries, flows)

    logger.info(
        "pcap '%s' ime-chambuliwa: packets=%s dns=%s flows=%s findings=%s na %s",
        file.filename,
        packets_read,
        len(dns_queries),
        len(flows),
        len(findings),
        _user.email,
    )

    return PcapAnalysis(
        file_name=file.filename or "capture.pcap",
        packets_read=packets_read,
        truncated=packets_read >= settings.pcap_max_packets,
        duration_seconds=duration,
        dns_queries=dns_queries[:500],
        flows=flows[:200],
        findings=findings,
        unique_domains=len({q.domain for q in dns_queries}),
        unique_external_ips=len(ext_ips),
    )
