"""Models za SIEM za kisasa: data sources, alerts, na SOAR response actions.

Hizi zinaunganisha detection pipeline:
  sensor -> SecurityEvent (raw + normalized) -> DetectionRule (correlation)
  -> Alert (lifecycle + SLA) -> Incident (case workspace) -> ResponseAction (SOAR).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.organization import Organization


class DataSource(UUIDMixin, TimestampMixin, Base):
    """Chanzo cha matukio (agent, NextDNS, pcap, syslog, sensor token).

    Inatumika kwenye "Data source health" page: status (healthy/degraded/offline)
    inakokotolewa kutoka `last_event_at` ikilinganishwa na sasa, na takwimu
    (events_24h, eps) zinakokotolewa kwenye read-time kutoka `security_events`.
    """

    __tablename__ = "data_sources"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    #: agent | nextdns | pcap | syslog | sensor | api
    type: Mapped[str] = mapped_column(String(24), default="sensor", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_event_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(400), nullable=True)
    events_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    organization: Mapped["Organization"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DataSource {self.name} ({self.type})>"


class Alert(UUIDMixin, TimestampMixin, Base):
    """Alert ya detection — kitu kinachopangwa kwenye "Alert Center".

    Tofauti na event moja, alert inajumuisha hit nyingi (dedup kwa `fingerprint`)
    na ina lifecycle halisi: new -> acknowledged/assigned/snoozed -> resolved,
    pamoja na SLA (`sla_due_at`) inayokokotolewa kutoka severity.
    """

    __tablename__ = "alerts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("detection_rules.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True, nullable=False)

    #: new | acknowledged | assigned | snoozed | resolved
    status: Mapped[str] = mapped_column(String(16), default="new", index=True, nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)

    #: Dedup key: rule_id + group value + indicator, kwa ajili ya kukusanya hits.
    fingerprint: Mapped[str] = mapped_column(String(200), index=True, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    #: [{type, value, label}] — devices, IPs, domains, accounts zinazohusika.
    entities: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Event ids zilizochangia alert hii (hifadhi ya juu tu).
    event_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: true = imewekwa alama ya false positive na analyst.
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.title} ({self.status})>"


class ResponseAction(UUIDMixin, TimestampMixin, Base):
    """Hatua ya SOAR (isolation, block, disable, snapshot) iliyorekodiwa.

    Inaweza kuendeshwa moja kwa moja (kwa mfano `block` kwenye NextDNS, `snapshot`
    kwa agent job) au kusimama kama "manual" — analyst atafanya kwa mikono —
    na kuandikwa kwenye rekodi ya kisa kama ushahidi.
    """

    __tablename__ = "response_actions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    #: isolate | block | disable | snapshot | notify
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    #: device | ip | domain | user | account
    target_type: Mapped[str] = mapped_column(String(24), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    #: pending | running | succeeded | failed | manual
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True, nullable=False)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ResponseAction {self.kind} {self.target} ({self.status})>"
