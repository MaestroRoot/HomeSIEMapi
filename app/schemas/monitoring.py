"""Schemas za devices, matukio, ingest, na sensor tokens."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel
from app.schemas.intel import Verdict

EventKind = Literal["dns", "flow"]
Severity = Literal["critical", "high", "medium", "low", "info"]


# --- Devices --------------------------------------------------------------


class DeviceRead(CamelModel):
    id: uuid.UUID
    name: str
    mac: str | None = None
    device_type: str
    last_ip: str | None = None
    hostname: str | None = None
    owner_name: str | None = None
    status: str
    discovered: bool
    tags: list[str] = []
    risk_score: int
    events_count: int
    last_seen_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class DeviceRegister(CamelModel):
    name: str = Field(min_length=1, max_length=120)
    mac: str | None = Field(default=None, max_length=17)
    device_type: str = Field(default="Unknown", max_length=32)
    last_ip: str | None = Field(default=None, max_length=45)
    hostname: str | None = Field(default=None, max_length=255)
    owner_name: str | None = Field(default=None, max_length=120)


class DeviceUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    device_type: str | None = Field(default=None, max_length=32)
    status: str | None = Field(default=None, max_length=16)
    tags: list[str] | None = Field(default=None, max_length=20)
    owner_name: str | None = Field(default=None, max_length=120)


class DeviceList(CamelModel):
    items: list[DeviceRead]
    total: int


# --- Matukio --------------------------------------------------------------


class SecurityEventRead(CamelModel):
    id: uuid.UUID
    device_id: uuid.UUID | None = None
    device_name: str | None = None
    kind: EventKind
    event_type: str | None = None
    src_ip: str | None = None
    src_mac: str | None = None
    domain: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    account: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    parent_process: str | None = None
    source: str | None = None
    verdict: Verdict
    severity: Severity
    pulse_count: int
    country: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    occurred_at: datetime | None = None
    created_at: datetime

    @field_serializer("id", "device_id")
    def _uuid_to_str(self, value: uuid.UUID | None) -> str | None:
        return str(value) if value else None


class EventList(CamelModel):
    items: list[SecurityEventRead]
    total: int


# --- Ingest (kutoka sensor) -----------------------------------------------


class IngestEvent(CamelModel):
    """Tukio ghafi kutoka sensor, kabla ya enrichment.

    `kind` (dns|flow) linabakia kwa ushirikiano na sensors za zamani; `event_type`
    linaruhusu sensors za kisasa kusema aina hasi (authentication, process, file...).
    `extra` ni map ya ziada ambayo itahifadhiwa kwenye `raw` na kusanifishwa.
    """

    kind: EventKind
    event_type: str | None = Field(default=None, max_length=24)
    src_ip: str | None = Field(default=None, max_length=45)
    src_mac: str | None = Field(default=None, max_length=17)
    domain: str | None = Field(default=None, max_length=255)
    dst_ip: str | None = Field(default=None, max_length=45)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    account: str | None = Field(default=None, max_length=120)
    process_name: str | None = Field(default=None, max_length=200)
    command_line: str | None = Field(default=None, max_length=4000)
    file_path: str | None = Field(default=None, max_length=500)
    parent_process: str | None = Field(default=None, max_length=200)
    #: Jina la chanzo kilichotuma (agent hostname, "nextdns", "pcap"...).
    source: str | None = Field(default=None, max_length=120)
    #: Unix epoch seconds ya tukio, kama sensor inayo.
    ts: float | None = None
    #: Vipengele vingine vyovyote vinavyotumwa na sensor (vitawekwa `raw`).
    extra: dict | None = None


class IngestBatch(CamelModel):
    events: list[IngestEvent] = Field(min_length=1, max_length=500)


class IngestResult(CamelModel):
    accepted: int
    flagged: int
    devices_touched: int


# --- Sensor tokens --------------------------------------------------------


class SensorTokenRead(CamelModel):
    id: uuid.UUID
    label: str
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class SensorTokenCreate(CamelModel):
    label: str = Field(min_length=1, max_length=80)


class SensorTokenCreated(SensorTokenRead):
    """Inarudishwa mara moja tu inapotengenezwa, ikiwa na token halisi."""

    token: str
