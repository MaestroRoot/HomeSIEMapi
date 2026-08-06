"""Kusoma pcap kwa tshark (async subprocess) na kutoa DNS + flows.

tshark ni blocking, hivyo tunatumia `asyncio.create_subprocess_exec`, si
`subprocess.run`, ili request moja isisimamishe server nzima.

USALAMA: kuchambua pcap ya mtu asiyeaminika ni hatari, Wireshark dissectors
zina historia ndefu ya CVEs. Tunaweka mipaka: ukubwa wa faili, idadi ya
packets (`-c`), na timeout. Bado, kwenye production hii inapaswa kukimbia
kwenye container/user mwenye ruhusa ndogo.
"""

from __future__ import annotations

import asyncio
import ipaddress

from app.core.config import settings
from app.core.errors import AppError, ServiceUnavailableError
from app.core.logging import get_logger
from app.schemas.pcap import DnsQuery, Flow

logger = get_logger(__name__)

_SEP = "\x1f"  # unit separator, haiwezekani kuwa ndani ya thamani ya field

#: DNS query type namba -> jina.
_QTYPE = {
    "1": "A",
    "28": "AAAA",
    "5": "CNAME",
    "15": "MX",
    "16": "TXT",
    "2": "NS",
    "6": "SOA",
    "12": "PTR",
    "33": "SRV",
    "65": "HTTPS",
}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


async def _run_tshark(args: list[str]) -> str:
    """Endesha tshark na rudisha stdout. Inarusha AppError kwa kushindwa."""
    cmd = [settings.tshark_path, *args]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ServiceUnavailableError(
            "Packet analysis is unavailable (tshark was not found on the server).",
            code="tshark_missing",
        ) from exc

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=settings.tshark_timeout
        )
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise AppError(
            "The capture took too long to analyse and was stopped.",
            code="pcap_timeout",
        ) from exc

    if proc.returncode != 0:
        msg = stderr.decode("utf-8", "replace")[:300]
        logger.error("tshark returncode=%s: %s", proc.returncode, msg)
        raise AppError(
            "The capture file could not be read. It may be corrupt or not a valid pcap.",
            code="pcap_unreadable",
        )
    return stdout.decode("utf-8", "replace")


def _base_args(path: str) -> list[str]:
    # -n: usisuluhishe majina (DNS/host), tunataka data ghafi na kasi.
    # -c: kikomo cha packets, ulinzi.
    return ["-r", path, "-n", "-c", str(settings.pcap_max_packets)]


async def extract_dns(path: str) -> list[DnsQuery]:
    """Toa maswali yote ya DNS (requests, si responses)."""
    args = [
        *_base_args(path),
        "-Y",
        "dns.flags.response == 0 && dns.qry.name",
        "-T",
        "fields",
        "-E",
        f"separator={_SEP}",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "dns.qry.name",
        "-e",
        "dns.qry.type",
    ]
    out = await _run_tshark(args)
    seen: set[tuple[str, str]] = set()
    queries: list[DnsQuery] = []
    for line in out.splitlines():
        if not line:
            continue
        cols = line.split(_SEP)
        if len(cols) < 5:
            continue
        time_s, ip4, ip6, domain, qtype = cols[0], cols[1], cols[2], cols[3], cols[4]
        src = ip4 or ip6 or "?"
        # dns.qry.name inaweza kuwa na majina mengi (comma) kwenye packet moja.
        domain = domain.split(",")[0].strip().lower()
        if not domain:
            continue
        key = (src, domain)
        if key in seen:
            continue
        seen.add(key)
        try:
            t = float(time_s) if time_s else None
        except ValueError:
            t = None
        queries.append(
            DnsQuery(
                time=t,
                src=src,
                domain=domain,
                qtype=_QTYPE.get(qtype.split(",")[0], qtype or "?"),
            )
        )
    return queries


async def extract_flows(path: str) -> tuple[list[Flow], int, float | None]:
    """Toa flows (packets zilizokusanywa kwa src/dst/port/proto).

    Inarudisha (flows, packets_read, duration_seconds).
    """
    args = [
        *_base_args(path),
        "-T",
        "fields",
        "-E",
        f"separator={_SEP}",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
        "-e",
        "frame.len",
        "-Y",
        "ip",
    ]
    out = await _run_tshark(args)

    agg: dict[tuple[str, str, int | None, str], list[int]] = {}
    packets_read = 0
    t_first: float | None = None
    t_last: float | None = None

    for line in out.splitlines():
        if not line:
            continue
        cols = line.split(_SEP)
        if len(cols) < 7:
            continue
        time_s, src, dst, proto, tcpp, udpp, length = cols[:7]
        if not src or not dst:
            continue
        packets_read += 1

        if time_s:
            try:
                t = float(time_s)
                t_first = t if t_first is None else min(t_first, t)
                t_last = t if t_last is None else max(t_last, t)
            except ValueError:
                pass

        port_raw = (tcpp or udpp or "").split(",")[0]
        port = int(port_raw) if port_raw.isdigit() else None
        try:
            nbytes = int(length) if length else 0
        except ValueError:
            nbytes = 0

        key = (src, dst, port, proto or "?")
        row = agg.get(key)
        if row is None:
            agg[key] = [1, nbytes]
        else:
            row[0] += 1
            row[1] += nbytes

    flows = [
        Flow(
            src=src,
            dst=dst,
            dst_port=port,
            protocol=proto,
            packets=count,
            bytes=nbytes,
        )
        for (src, dst, port, proto), (count, nbytes) in agg.items()
    ]
    # Kubwa kwanza (packets nyingi = flow muhimu zaidi).
    flows.sort(key=lambda f: f.packets, reverse=True)

    duration = None
    if t_first is not None and t_last is not None:
        duration = round(t_last - t_first, 3)

    return flows, packets_read, duration


def external_ips(flows: list[Flow]) -> list[str]:
    """IP za nje za kipekee kutoka kwenye destinations (za enrichment)."""
    ips: list[str] = []
    seen: set[str] = set()
    for f in flows:
        if f.dst in seen or _is_private(f.dst):
            continue
        seen.add(f.dst)
        ips.append(f.dst)
    return ips
