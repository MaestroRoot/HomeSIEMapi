"""Models za ufuatiliaji: devices, matukio, na tokens za sensor.

Hii ndiyo hatua inayounganisha "sensor yoyote" (PcapUpload, tshark-live, au
DNS resolver) na dashboard: sensor inatuma matukio -> backend ina-enrich
(GeoIP + OTX) -> ina-map kwa device -> inaonyesha.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.organization import Organization


class Agent(UUIDMixin, TimestampMixin, Base):
    """Agent iliyosajiliwa kwenye host (PC/server).

    Mtu anaendesha command MARA MOJA, agent inajisajili hapa na kubaki
    inaendesha. Baada ya hapo dashboard inatuma `AgentJob` (scan, forensics,
    n.k.) na agent inazitekeleza bila mtu kurudia command.
    """

    __tablename__ = "agents"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    os: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    #: Ni nini agent inaweza kufanya: ["scan","forensics","logs","capture"].
    capabilities: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Kifaa (Device) kinacholingana, kwa MAC/IP, ikiwa kinajulikana.
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Agent {self.hostname}>"


class AgentJob(UUIDMixin, TimestampMixin, Base):
    """Kazi inayotumwa kwa agent na dashboard (scan/forensics/...)."""

    __tablename__ = "agent_jobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: scan | forensics | logs | capture
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: pending | running | done | error
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True, nullable=False)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AgentJob {self.kind} {self.status}>"


class Device(UUIDMixin, TimestampMixin, Base):
    """Kifaa kinachofuatiliwa.

    Kinatambuliwa kwa **MAC** (namba ya kudumu ya network card), sio IP, kwa
    sababu IP za nyumbani hubadilika kila DHCP inapotoa lease mpya. `last_ip`
    ni ya sasa tu. Vifaa vinaweza kusajiliwa na mtumiaji, au kugunduliwa
    kiotomatiki na sensor (`discovered=True`).
    """

    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "mac", name="uq_device_org_mac"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: MAC iliyorekebishwa kuwa herufi ndogo, "aa:bb:cc:dd:ee:ff". Nullable kwa
    #: sababu matukio ya pcap (L3) huwa na IP pekee bila MAC.
    mac: Mapped[str | None] = mapped_column(String(17), index=True, nullable=True)
    device_type: Mapped[str] = mapped_column(String(32), default="Unknown", nullable=False)
    last_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    #: True = imegunduliwa na sensor, sio kusajiliwa na mtu. UI inaweza kumwomba
    #: mtumiaji aipe jina.
    discovered: Mapped[bool] = mapped_column(default=False, nullable=False)
    #: Lebo za kupanga vifaa (site, team, criticality...).
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    #: Jina la mtumiaji aliyeteuliwa kwenye kifaa hiki (kwa UEBA).
    owner_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization: Mapped["Organization"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Device {self.name} {self.mac or self.last_ip}>"


class SecurityEvent(UUIDMixin, TimestampMixin, Base):
    """Tukio moja lililopokewa kutoka sensor, baada ya enrichment.

    Sensor inatuma **muhtasari** (DNS query au flow), sio kila packet. Kila
    tukio linahifadhiwa na hukumu yake (`verdict`) na eneo (`country`/`asn`).
    """

    __tablename__ = "security_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    #: "dns" au "flow".
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    verdict: Mapped[str] = mapped_column(String(16), default="unknown", index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True, nullable=False)
    pulse_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asn_org: Mapped[str | None] = mapped_column(String(128), nullable=True)

    occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SecurityEvent {self.kind} {self.domain or self.dst_ip} {self.verdict}>"


class NotificationChannel(UUIDMixin, TimestampMixin, Base):
    """Mahali pa kutuma arifa (Slack/Discord/email/webhook/PagerDuty)."""

    __tablename__ = "notification_channels"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: slack | discord | email | webhook | pagerduty
    type: Mapped[str] = mapped_column(String(24), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    #: webhook URL au email address.
    target: Mapped[str] = mapped_column(String(1024), nullable=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="high", nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<NotificationChannel {self.type} {self.name}>"


class LogEntry(UUIDMixin, TimestampMixin, Base):
    """Mstari mmoja wa log kutoka kwa agent (Windows Event Log, syslog, faili)."""

    __tablename__ = "log_entries"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    host: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    level: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Vulnerability(UUIDMixin, TimestampMixin, Base):
    """Udhaifu uliogunduliwa na scanner kwenye kifaa fulani."""

    __tablename__ = "vulnerabilities"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fix: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: open | fixed | accepted
    status: Mapped[str] = mapped_column(String(16), default="open", index=True, nullable=False)


class ForensicSnapshot(UUIDMixin, TimestampMixin, Base):
    """Picha ya wakati mmoja ya host: processes + connections (kutoka psutil)."""

    __tablename__ = "forensic_snapshots"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    processes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    connections: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)


class SoftwarePackage(UUIDMixin, TimestampMixin, Base):
    """Programu moja iliyosakinishwa kwenye host (kutoka agent `software` job)."""

    __tablename__ = "software_packages"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(60), default="", nullable=False)
    publisher: Mapped[str] = mapped_column(String(120), default="", nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SoftwarePackage {self.name} {self.version}>"


class CloudflareGatewayConfig(UUIDMixin, TimestampMixin, Base):
    """Config ya Cloudflare Gateway ya org moja. Backend poller huvuta DNS logs
    kutoka Cloudflare Zero Trust API na kuziingiza kwa org husika (multi-tenant).

    Reseller model: single Cloudflare account (from settings), location per org.
    """

    __tablename__ = "cloudflare_gateway_configs"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_cloudflare_gateway_org"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    location_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    location_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    doh_subdomain: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(200), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CloudflareGatewayConfig org={self.organization_id} location={self.location_id}>"

    @property
    def doh_hostname(self) -> str | None:
        """DoH hostname for this org's location (uses Cloudflare's doh_subdomain)."""
        from app.core.config import settings
        if settings.cloudflare_doh_domain:
            return f"org-{self.organization_id.hex[:8]}.{settings.cloudflare_doh_domain}"
        if self.doh_subdomain:
            return f"{self.doh_subdomain}.dns.cloudflare-gateway.com"
        return None


class CollectionStream(UUIDMixin, TimestampMixin, Base):
    """Ukusanyaji unaoendelea (capture/logs) uliohifadhiwa server-side.

    Ukiwa `enabled`, agent inapopoll (bila kujali dashboard imefunguliwa au la),
    server inatengeneza job mpya ya aina hii endapo hakuna inayoendelea — hivyo
    ukusanyaji unaendelea muda wote hadi mtumiaji abonyeze Stop.
    """

    __tablename__ = "collection_streams"
    __table_args__ = (UniqueConstraint("agent_id", "kind", name="uq_stream_agent_kind"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: capture | logs
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CollectionStream {self.kind} enabled={self.enabled}>"


class DiscoverySchedule(UUIDMixin, TimestampMixin, Base):
    """Ratiba ya kufanya network discovery sweep kiotomatiki kupitia agent."""

    __tablename__ = "discovery_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: Subnet ya ku-sweep, mfano "192.168.1.0/24". Tupu = agent aikisie.
    subnet: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    #: hourly | daily | weekly
    frequency: Mapped[str] = mapped_column(String(16), default="daily", nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DiscoverySchedule {self.subnet} {self.frequency}>"


class DetectionRule(UUIDMixin, TimestampMixin, Base):
    """Kanuni ya kugundua: IF <condition> THEN alert. Inatathminiwa wakati wa
    ingest juu ya kila event."""

    __tablename__ = "detection_rules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    #: verdict_is | domain_contains | country_is | pulse_count_gte
    condition_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    action: Mapped[str] = mapped_column(String(16), default="alert", nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="custom", nullable=False)

    hits: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    false_positives: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DetectionRule {self.name}>"


class ReportSchedule(UUIDMixin, TimestampMixin, Base):
    """Ratiba ya kutuma ripoti kiotomatiki (daily/weekly/monthly)."""

    __tablename__ = "report_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    #: weekly | monthly | executive | incident
    kind: Mapped[str] = mapped_column(String(24), default="weekly", nullable=False)
    #: daily | weekly | monthly
    frequency: Mapped[str] = mapped_column(String(16), default="weekly", nullable=False)
    to_whole_team: Mapped[bool] = mapped_column(default=False, nullable=False)
    recipients: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ReportSchedule {self.kind} {self.frequency}>"


class Incident(UUIDMixin, TimestampMixin, Base):
    """Kisa cha usalama kinachosimamiwa na mtu (triage -> closed)."""

    __tablename__ = "incidents"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="new", index=True, nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    #: [{author, time, body}]
    notes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.title} ({self.status})>"


class SensorToken(UUIDMixin, TimestampMixin, Base):
    """Funguo inayoruhusu sensor (box/agent) kutuma matukio.

    Token yenyewe HAIHIFADHIWI, tunahifadhi SHA-256 yake pekee, ni utaratibu
    ule ule wa `Invitation.token_hash` na OTP. Inaonyeshwa mara moja tu
    inapotengenezwa.
    """

    __tablename__ = "sensor_tokens"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String(80), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SensorToken {self.label}>"
