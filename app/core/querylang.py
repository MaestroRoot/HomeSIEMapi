"""SIEM query language: parse "domain:evil.com severity:high -verdict:unknown" kwenye filters.

Mtumiaji anaweza kuandika maneno huru (kutafutwa kote) na vigezo vya `key:value`.
Orodha ya vigezo vinavyotambulika:

    domain, ip, src, src_ip, dst, dst_ip, port, dst_port, protocol,
    kind, event_type, verdict, severity, country, asn, device, source,
    account, user, process, file, has

    after:<iso|ts>, before:<iso|ts>  — dirisha la wakati
    -key:value                     — negation (nje ya)
    host:value                     — alias ya device
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

#: (muda, negated, key, value) — key iko lowercase tayari.
_TOKEN_RE = re.compile(r"(-)?([a-zA-Z_]+):(\S+)")
_FREETEXT_RE = re.compile(r"\S+")

_ALIASES: dict[str, str] = {
    "ip": "ip",
    "src": "src_ip",
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "dst": "dst_ip",
    "dst_ip": "dst_ip",
    "dest": "dst_ip",
    "port": "dst_port",
    "dst_port": "dst_port",
    "device": "device",
    "host": "device",
    "user": "account",
    "account": "account",
    "process": "process_name",
    "proc": "process_name",
    "file": "file_path",
    "type": "event_type",
    "event_type": "event_type",
    "kind": "kind",
    "verdict": "verdict",
    "severity": "severity",
    "country": "country",
    "asn": "asn",
    "domain": "domain",
    "protocol": "protocol",
    "source": "source",
    "has": "has",
    "after": "after",
    "before": "before",
}

#: Vigezo vya wakati (si columns).
_TIME_KEYS = {"after", "before"}
#: Vigezo visivyo vya DB — vinasindikwa tofauti.
_SPECIAL_KEYS = {"has"} | _TIME_KEYS


@dataclass
class ParsedQuery:
    free: list[str] = field(default_factory=list)
    fields: dict[str, list[tuple[str, bool]]] = field(default_factory=dict)
    after: float | None = None
    before: float | None = None
    has: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return (
            not self.free
            and not self.fields
            and not self.has
            and self.after is None
            and self.before is None
        )


def _to_ts(value: str) -> float | None:
    """Kubali epoch sekunde au ISO date/time."""
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.timestamp()
    except ValueError:
        return None


def parse(query: str) -> ParsedQuery:
    """Gawa query kwenye sehemu. Vigezo visivyotambulika vinachukuliwa maneno huru."""
    parsed = ParsedQuery()

    # Tokens za key:value — ziondoe kwenye string ili ziweze kusindikwa mara moja.
    for match in _TOKEN_RE.finditer(query):
        negated = match.group(1) is not None
        raw_key = match.group(2).lower()
        value = match.group(3)

        key = _ALIASES.get(raw_key)
        if key is None:
            # Vigezo visivyotambulika vinabaki kama maneno huru.
            continue
        if key in _TIME_KEYS:
            ts = _to_ts(value)
            if ts is None:
                continue
            if key == "after":
                parsed.after = ts
            else:
                parsed.before = ts
        elif key == "has":
            parsed.has.append(value)
        else:
            parsed.fields.setdefault(key, []).append((value, negated))

    # Maneno huru = yale yasiyokuwa sehemu ya key:value tokeni.
    spans = [m.span() for m in _TOKEN_RE.finditer(query)]
    last_end = 0
    for start, end in spans:
        parsed.free.extend(_FREETEXT_RE.findall(query[last_end:start]))
        last_end = end
    parsed.free.extend(_FREETEXT_RE.findall(query[last_end:]))

    # Ondoa duplications kwenye free (baadhi yanaweza kuwa tokeni zilizokataliwa).
    return parsed
