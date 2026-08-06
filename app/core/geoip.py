"""GeoIP lookup ya ndani (offline) kwa MaxMind GeoLite2.

Hakuna network call kwa kila IP. Faili za `.mmdb` zinasomwa moja kwa moja
kutoka diski (memory-mapped), hivyo lookup ni ya microseconds na hakuna rate
limit. Hii ndiyo maana tunaweza ku-enrich *kila* IP kwenye pcap bila gharama.

Readers zinafunguliwa mara moja na kutumika tena. `geoip2.database.Reader` ni
salama kusomwa na threads/coroutines nyingi kwa wakati mmoja, na read yenyewe
ni ya haraka vya kutosha kutoiweka kwenye threadpool.

Muhimu: `geoip2` inarusha `AddressNotFoundError` kwa IP zisizopo (za ndani kama
192.168.x, na baadhi za nje). Hairudishi None. Kila lookup lazima ikamate hilo,
vinginevyo IP ya LAN itaangusha request.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import geoip2.database
import geoip2.errors

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.intel import GeoLocation

logger = get_logger(__name__)


@lru_cache(maxsize=1)
def _city_reader() -> geoip2.database.Reader | None:
    path = settings.geoip_dir / "GeoLite2-City.mmdb"
    if not path.is_file():
        return None
    return geoip2.database.Reader(str(path))


@lru_cache(maxsize=1)
def _asn_reader() -> geoip2.database.Reader | None:
    path = settings.geoip_dir / "GeoLite2-ASN.mmdb"
    if not path.is_file():
        return None
    return geoip2.database.Reader(str(path))


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def lookup(ip: str) -> GeoLocation | None:
    """Rudisha eneo + ASN ya IP, au None ikiwa haipatikani.

    IP za ndani (LAN) zinarudisha `GeoLocation` yenye `isPrivate=True` bila
    kuulizwa MaxMind, kwa sababu hazipo kwenye database wala hazina eneo.
    """
    city = _city_reader()
    asn = _asn_reader()
    if city is None:
        # Database haijapakuliwa. Hii inashughulikiwa na health check;
        # hapa turudishe None kimya ili enrichment iendelee bila geo.
        return None

    if _is_private(ip):
        return GeoLocation(ip=ip, is_private=True)

    country = city_name = None
    latitude = longitude = None
    try:
        res = city.city(ip)
        country = res.country.name
        country_code = res.country.iso_code
        city_name = res.city.name
        latitude = res.location.latitude
        longitude = res.location.longitude
    except geoip2.errors.AddressNotFoundError:
        country = country_code = None
    except ValueError:
        return None

    asn_number = asn_org = None
    if asn is not None:
        try:
            a = asn.asn(ip)
            asn_number = a.autonomous_system_number
            asn_org = a.autonomous_system_organization
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass

    return GeoLocation(
        ip=ip,
        is_private=False,
        country=country,
        country_code=country_code,
        city=city_name,
        latitude=latitude,
        longitude=longitude,
        asn=asn_number,
        asn_org=asn_org,
    )
