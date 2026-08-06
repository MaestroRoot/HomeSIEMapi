"""Threat intel kupitia AlienVault OTX (async, httpx).

Hatumii SDK ya `OTXv2` kwa sababu ni synchronous (juu ya `requests`) na
ingesimamisha event loop nzima kwa kila lookup. API ya OTX ni GET rahisi zenye
header moja, hivyo `httpx.AsyncClient` inatosha, kwa mtindo ule ule wa
`app/core/email.py`.

ONYO la usahihi: OTX hairudishi score. Inarudisha tu idadi ya "pulses"
zinazogusa indicator. Kuwa kwenye pulse SI sawa na kuwa malicious, watafiti
huweka pia infrastructure ya kawaida kwa context. Hukumu hapa ni *heuristic*
ya kuanzia. Field `reputation` ya OTX imeachwa kufanya kazi (0 karibu kila
mara), hivyo hatuitegemei.
"""

from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.core.errors import ServiceUnavailableError
from app.core.logging import get_logger
from app.schemas.intel import IndicatorType, IntelResult, Verdict

logger = get_logger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
_TIMEOUT = 15.0

#: Idadi ndogo ya pulses (bila kuwa kwenye allowlist) inayotosha kuiweka
#: indicator kama "suspicious", yaani inastahili kuangaliwa.
_SUSPICIOUS_AT = 1


def classify(value: str) -> IndicatorType:
    """Tambua aina ya indicator kutoka umbo lake. Inalingana na `classify()`
    ya frontend (IocScanner.tsx)."""
    v = value.strip()
    lower = v.lower()
    if _is_hex(v, 64):
        return "sha256"
    if _is_hex(v, 40):
        return "sha1"
    if _is_hex(v, 32):
        return "md5"
    if lower.startswith(("http://", "https://")):
        return "url"
    if _looks_like_ip(v):
        return "ip"
    return "domain"


def _is_hex(value: str, length: int) -> bool:
    if len(value) != length:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


#: Section ya OTX kwa kila aina ya indicator.
_PATHS: dict[IndicatorType, str] = {
    "ip": "IPv4/{v}/general",
    "domain": "domain/{v}/general",
    "url": "url/{v}/general",
    "sha256": "file/{v}/general",
    "sha1": "file/{v}/general",
    "md5": "file/{v}/general",
}


def _verdict_for(pulse_count: int, whitelisted: bool) -> tuple[Verdict, str]:
    """Hukumu kutoka OTX pekee.

    Muhimu, na ndiyo tofauti kubwa: OTX HAITOI score. Idadi ya pulses si
    kipimo cha uovu, tovuti maarufu (wikipedia.org, GitHub) huonekana kwenye
    pulses nyingi kama context. Kwa hiyo:

    * Iko kwenye allowlist kubwa (Alexa/Majestic/Akamai/whitelist) -> `clean`,
      hata kama ina pulses nyingi. Hii inaua false positives.
    * Haipo popote -> `unknown` (sio `clean`, OTX haijui tu).
    * Ina pulses lakini haiko kwenye allowlist -> `suspicious`, inastahili
      kuangaliwa. HATUISEMI `malicious` kwa OTX pekee, kwa sababu IP ya
      GitHub na IP ya C2 zina profile ile ile hapa. `malicious` itarudi pale
      feed ya pili yenye confidence halisi (AbuseIPDB) itakapoongezwa.
    """
    if whitelisted:
        return "clean", "On major allow-lists (Alexa/Majestic/Akamai). Treated as legitimate."
    if pulse_count >= _SUSPICIOUS_AT:
        return (
            "suspicious",
            f"Appears in {pulse_count} OTX threat report(s) and is not on any allow-list. "
            "Worth reviewing, being referenced in a report is a lead, not proof.",
        )
    return "unknown", "Not present in any OTX threat report. This is not proof it is safe."


#: Cache ndogo ya matokeo, ili stream ya ingest isipige OTX kwa domain ile
#: ile mara kwa mara. Domains hujirudia sana kwenye traffic.
_CACHE_TTL = 6 * 60 * 60  # sekunde 6 saa
_cache: dict[str, tuple[float, IntelResult]] = {}


async def lookup_cached(value: str, itype: IndicatorType | None = None) -> IntelResult:
    """Kama `lookup`, lakini inakumbuka matokeo kwa muda (`_CACHE_TTL`)."""
    value = value.strip()
    itype = itype or classify(value)
    key = f"{itype}:{value.lower()}"
    hit = _cache.get(key)
    now = time.monotonic()
    if hit is not None and hit[0] > now:
        return hit[1]
    result = await lookup(value, itype)
    _cache[key] = (now + _CACHE_TTL, result)
    return result


async def lookup(value: str, itype: IndicatorType | None = None) -> IntelResult:
    """Uliza OTX kuhusu indicator moja. Haina enrichment ya GeoIP, hiyo
    inaongezwa na endpoint ili module hii ibaki na jukumu moja."""
    if not settings.otx_api_key:
        raise ServiceUnavailableError(
            "Threat intelligence is not configured (OTX_API_KEY is missing).",
            code="otx_unconfigured",
        )

    value = value.strip()
    itype = itype or classify(value)
    path = _PATHS[itype].format(v=quote(value, safe=""))
    url = f"{_OTX_BASE}/{path}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
            resp = await http.get(url, headers={"X-OTX-API-KEY": settings.otx_api_key})
    except httpx.HTTPError as exc:
        logger.error("OTX haipatikani: %s", exc)
        raise ServiceUnavailableError(
            "The threat intelligence service is unreachable.", code="otx_unreachable"
        ) from exc

    if resp.status_code == 404:
        # OTX inarudisha 404 kwa indicator isiyojulikana kabisa.
        verdict, rationale = _verdict_for(0, whitelisted=False)
        return IntelResult(indicator=value, type=itype, verdict=verdict, rationale=rationale)

    if resp.status_code >= 300:
        logger.error("OTX imekataa (%s): %s", resp.status_code, resp.text[:300])
        raise ServiceUnavailableError(
            "The threat intelligence service returned an error.", code="otx_error"
        )

    data = resp.json()
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    pulse_count = int(pulse_info.get("count") or len(pulses))

    # `validation` inaorodhesha allowlists (Alexa/Majestic/Akamai/whitelist)
    # ambazo indicator imo. Ipo -> indicator halali maarufu. `false_positive`
    # ni orodha ya wale walioripoti kimakosa, hiyo pia ni ishara ya usalama.
    whitelisted = bool(data.get("validation")) or bool(data.get("false_positive"))

    tags: list[str] = []
    first_seen: str | None = None
    for pulse in pulses:
        for tag in pulse.get("tags") or []:
            if tag not in tags:
                tags.append(tag)
        created = pulse.get("created")
        if created and (first_seen is None or created < first_seen):
            first_seen = created

    verdict, rationale = _verdict_for(pulse_count, whitelisted)
    return IntelResult(
        indicator=value,
        type=itype,
        verdict=verdict,
        pulse_count=pulse_count,
        tags=tags[:12],
        first_seen=first_seen,
        rationale=rationale,
    )
