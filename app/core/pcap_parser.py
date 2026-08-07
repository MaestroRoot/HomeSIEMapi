"""Pure-Python pcap parser — no tshark dependency.

Reads .pcap / .pcapng / .cap files using only the `struct` module.
Extracts DNS queries and IP flows, sufficient for OTX + GeoIP enrichment.

Limitations vs tshark:
- Only handles Ethernet (link type 1) and Linux SLL (link type 113).
- IPv6 DNS queries are skipped (A/AAAA only via IPv4 UDP).
- No deep protocol dissection (just TCP/UDP port numbers).

These limits are acceptable for the HomeSIEM upload flow: the AI
summarises the enriched results, so approximate flow-level data is enough.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import defaultdict

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.pcap import DnsQuery, Flow

logger = get_logger(__name__)

# pcap global header: magic(4) + version_major(2) + version_minor(2) +
# thiszone(4) + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
_PCAP_HDR_FMT = "<IHHiIII"
_PCAP_HDR_SIZE = struct.calcsize(_PCAP_HDR_FMT)

# pcap packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16 bytes
_PKT_HDR_FMT = "<IIII"
_PKT_HDR_SIZE = struct.calcsize(_PKT_HDR_FMT)

_MAGIC_NATIVE = 0xA1b2C3d4
_MAGIC_SWAPPED = 0xD4C3B2A1
_MAGIC_NANO_NATIVE = 0xA1B23C4D
_MAGIC_NANO_SWAPPED = 0x4D3CB2A1

_LINKTYPE_ETHERNET = 1
_LINKTYPE_SLL = 113  # Linux cooked capture

_ETH_HDR_SIZE = 14
_SLL_HDR_SIZE = 16
_IP_MIN_HDR = 20

_PROTO_UDP = 17
_PROTO_TCP = 6

_DNS_PORT = 53


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


def _parse_dns_name(data: bytes, offset: int) -> str | None:
    """RFC 1035 name decomposition: sequence of length-prefixed labels, ending with \\x00."""
    parts: list[str] = []
    max_jumps = 10  # prevent infinite loops on malformed data
    jumps = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        # pointer (two high bits set)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return None
            if jumps >= max_jumps:
                return None
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            offset = pointer
            jumps += 1
            continue
        offset += 1
        if offset + length > len(data):
            return None
        parts.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(parts) if parts else None


def _parse_dns_query(data: bytes) -> tuple[str | None, str]:
    """Extract the first DNS query name + type from a DNS payload.

    Returns (domain, qtype_str) or (None, "?") on failure.
    """
    if len(data) < 12:
        return None, "?"
    # Skip header (11 bytes: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2))
    qdcount = struct.unpack_from("!H", data, 4)[0]
    if qdcount < 1:
        return None, "?"
    offset = 12
    domain = _parse_dns_name(data, offset)
    if domain is None:
        return None, "?"
    # Advance past the name to reach the QTYPE field
    # Re-scan to find where the name ends
    scan = 12
    while scan < len(data):
        ln = data[scan]
        if ln == 0:
            scan += 1
            break
        if (ln & 0xC0) == 0xC0:
            scan += 2
            break
        scan += 1 + ln
    if scan + 2 > len(data):
        return domain, "?"
    qtype = struct.unpack_from("!H", data, scan)[0]
    qtype_map = {
        1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
        2: "NS", 6: "SOA", 12: "PTR", 33: "SRV", 65: "HTTPS",
    }
    return domain, qtype_map.get(qtype, str(qtype))


def extract_dns(path: str) -> list[DnsQuery]:
    """Read a pcap file and return DNS queries (requests only)."""
    queries: list[DnsQuery] = []
    seen: set[tuple[str, str]] = set()
    max_packets = settings.pcap_max_packets

    try:
        with open(path, "rb") as f:
            # --- Global header ---
            hdr = f.read(_PCAP_HDR_SIZE)
            if len(hdr) < _PCAP_HDR_SIZE:
                logger.error("pcap header too short (%d bytes)", len(hdr))
                return queries

            magic = struct.unpack_from("<I", hdr, 0)[0]
            if magic == _MAGIC_NATIVE:
                endian = "<"
                nano = False
            elif magic == _MAGIC_SWAPPED:
                endian = ">"
                nano = False
            elif magic == _MAGIC_NANO_NATIVE:
                endian = "<"
                nano = True
            elif magic == _MAGIC_SWAPPED:
                endian = ">"
                nano = True
            else:
                # Try big-endian
                magic_be = struct.unpack_from(">I", hdr, 0)[0]
                if magic_be == _MAGIC_NATIVE:
                    endian = ">"
                    nano = False
                elif magic_be == _MAGIC_NANO_NATIVE:
                    endian = ">"
                    nano = True
                else:
                    logger.error("unknown pcap magic: 0x%08x", magic)
                    return queries

            _ver_major, _ver_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
                endian + "HHiIII", hdr[4:]
            )

            # --- Packet loop ---
            pkt_count = 0
            while pkt_count < max_packets:
                pkt_hdr = f.read(_PKT_HDR_SIZE)
                if len(pkt_hdr) < _PKT_HDR_SIZE:
                    break
                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", pkt_hdr)
                pkt_count += 1

                if incl_len > 200_000_000:  # sanity check
                    break
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                timestamp = float(ts_sec) + (ts_usec / 1_000_000_000 if nano else ts_usec / 1_000_000)

                # --- Strip link-layer header ---
                if linktype == _LINKTYPE_ETHERNET:
                    if len(raw) < _ETH_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 12)[0]
                    ip_offset = _ETH_HDR_SIZE
                    # 802.1Q VLAN tag
                    if ethertype == 0x8100:
                        if len(raw) < _ETH_HDR_SIZE + 4:
                            continue
                        ethertype = struct.unpack_from("!H", raw, _ETH_HDR_SIZE + 2)[0]
                        ip_offset = _ETH_HDR_SIZE + 4
                    if ethertype != 0x0800:  # not IPv4
                        continue
                elif linktype == _LINKTYPE_SLL:
                    if len(raw) < _SLL_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 14)[0]
                    ip_offset = _SLL_HDR_SIZE
                    if ethertype != 0x0800:
                        continue
                else:
                    # Assume Ethernet for unknown types
                    if len(raw) < _ETH_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 12)[0]
                    ip_offset = _ETH_HDR_SIZE
                    if ethertype != 0x0800:
                        continue

                # --- IP header ---
                if len(raw) < ip_offset + _IP_MIN_HDR:
                    continue
                ip_hdr = raw[ip_offset:]
                version_ihl = ip_hdr[0]
                ip_version = (version_ihl >> 4) & 0xF
                if ip_version != 4:
                    continue
                ihl = (version_ihl & 0xF) * 4
                if ihl < _IP_MIN_HDR:
                    continue
                total_len = struct.unpack_from("!H", ip_hdr, 2)[0]
                proto = ip_hdr[9]
                src_ip = f"{ip_hdr[12]}.{ip_hdr[13]}.{ip_hdr[14]}.{ip_hdr[15]}"
                dst_ip = f"{ip_hdr[16]}.{ip_hdr[17]}.{ip_hdr[18]}.{ip_hdr[19]}"

                # --- UDP DNS ---
                if proto == _PROTO_UDP:
                    udp_offset = ip_offset + ihl
                    if len(raw) < udp_offset + 8:
                        continue
                    udp_hdr = raw[udp_offset:]
                    src_port, dst_port = struct.unpack("!HH", udp_hdr[:4])
                    dns_offset = udp_offset + 8
                    if src_port == _DNS_PORT or dst_port == _DNS_PORT:
                        dns_data = raw[dns_offset:]
                        # Only requests (QR bit = 0)
                        if len(dns_data) >= 2 and (dns_data[2] & 0x80) == 0:
                            domain, qtype = _parse_dns_query(dns_data)
                            if domain:
                                domain = domain.lower()
                                key = (src_ip, domain)
                                if key not in seen:
                                    seen.add(key)
                                    queries.append(
                                        DnsQuery(
                                            time=timestamp,
                                            src=src_ip,
                                            domain=domain,
                                            qtype=qtype,
                                        )
                                    )

    except Exception as exc:
        logger.error("pcap_parser.extract_dns failed: %s", exc)

    return queries


def extract_flows(path: str) -> tuple[list[Flow], int, float | None]:
    """Read a pcap file and return aggregated IP flows.

    Returns (flows, packets_read, duration_seconds).
    """
    agg: dict[tuple[str, str, int | None, str], list[int]] = {}
    packets_read = 0
    t_first: float | None = None
    t_last: float | None = None
    max_packets = settings.pcap_max_packets

    try:
        with open(path, "rb") as f:
            hdr = f.read(_PCAP_HDR_SIZE)
            if len(hdr) < _PCAP_HDR_SIZE:
                return [], 0, None

            magic = struct.unpack_from("<I", hdr, 0)[0]
            if magic == _MAGIC_NATIVE:
                endian = "<"
                nano = False
            elif magic == _MAGIC_SWAPPED:
                endian = ">"
                nano = False
            elif magic == _MAGIC_NANO_NATIVE:
                endian = "<"
                nano = True
            elif magic == _MAGIC_SWAPPED:
                endian = ">"
                nano = True
            else:
                magic_be = struct.unpack_from(">I", hdr, 0)[0]
                if magic_be == _MAGIC_NATIVE:
                    endian = ">"
                    nano = False
                elif magic_be == _MAGIC_NANO_NATIVE:
                    endian = ">"
                    nano = True
                else:
                    return [], 0, None

            _ver_major, _ver_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
                endian + "HHiIII", hdr[4:]
            )

            while packets_read < max_packets:
                pkt_hdr = f.read(_PKT_HDR_SIZE)
                if len(pkt_hdr) < _PKT_HDR_SIZE:
                    break
                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", pkt_hdr)
                packets_read += 1

                if incl_len > 200_000_000:
                    break
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                timestamp = float(ts_sec) + (ts_usec / 1_000_000_000 if nano else ts_usec / 1_000_000)
                t_first = timestamp if t_first is None else min(t_first, timestamp)
                t_last = timestamp if t_last is None else max(t_last, timestamp)

                # --- Strip link-layer ---
                if linktype == _LINKTYPE_ETHERNET:
                    if len(raw) < _ETH_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 12)[0]
                    ip_offset = _ETH_HDR_SIZE
                    if ethertype == 0x8100:
                        if len(raw) < _ETH_HDR_SIZE + 4:
                            continue
                        ethertype = struct.unpack_from("!H", raw, _ETH_HDR_SIZE + 2)[0]
                        ip_offset = _ETH_HDR_SIZE + 4
                    if ethertype != 0x0800:
                        continue
                elif linktype == _LINKTYPE_SLL:
                    if len(raw) < _SLL_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 14)[0]
                    ip_offset = _SLL_HDR_SIZE
                    if ethertype != 0x0800:
                        continue
                else:
                    if len(raw) < _ETH_HDR_SIZE:
                        continue
                    ethertype = struct.unpack_from("!H", raw, 12)[0]
                    ip_offset = _ETH_HDR_SIZE
                    if ethertype != 0x0800:
                        continue

                # --- IP header ---
                if len(raw) < ip_offset + _IP_MIN_HDR:
                    continue
                ip_hdr = raw[ip_offset:]
                version_ihl = ip_hdr[0]
                ip_version = (version_ihl >> 4) & 0xF
                if ip_version != 4:
                    continue
                ihl = (version_ihl & 0xF) * 4
                if ihl < _IP_MIN_HDR:
                    continue
                proto_num = ip_hdr[9]
                src_ip = f"{ip_hdr[12]}.{ip_hdr[13]}.{ip_hdr[14]}.{ip_hdr[15]}"
                dst_ip = f"{ip_hdr[16]}.{ip_hdr[17]}.{ip_hdr[18]}.{ip_hdr[19]}"

                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))

                # Port extraction
                port: int | None = None
                transport_offset = ip_offset + ihl
                if proto_num in (6, 17) and len(raw) >= transport_offset + 4:
                    port = struct.unpack_from("!H", raw, transport_offset + 2)[0]  # dst port

                nbytes = min(incl_len, _orig_len) if _orig_len else incl_len

                key = (src_ip, dst_ip, port, proto_name)
                row = agg.get(key)
                if row is None:
                    agg[key] = [1, nbytes]
                else:
                    row[0] += 1
                    row[1] += nbytes

    except Exception as exc:
        logger.error("pcap_parser.extract_flows failed: %s", exc)

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
    flows.sort(key=lambda f: f.packets, reverse=True)

    duration = None
    if t_first is not None and t_last is not None:
        duration = round(t_last - t_first, 3)

    return flows, packets_read, duration


def external_ips(flows: list[Flow]) -> list[str]:
    """Unique external (non-private) destination IPs for enrichment."""
    ips: list[str] = []
    seen: set[str] = set()
    for f in flows:
        if f.dst in seen or _is_private(f.dst):
            continue
        seen.add(f.dst)
        ips.append(f.dst)
    return ips
