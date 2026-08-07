"""Models za UEBA (User and Entity Behavior Analytics).

Hii inahifadhi mifumo ya kawaida ya tabia ya mtumiaji, anomalies zilizogunduliwa,
na risk scores za kila mtumiaji kulingana na data kutoka modules zote za dashboard.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


class UserBaseline(UUIDMixin, TimestampMixin, Base):
    """Mfumo wa kawaida wa tabia ya mtumiaji (owner_name).

    Inajengwa na data ya siku 14 za kwanza. Inasasishwa kwa wiki.
    """

    __tablename__ = "user_baselines"
    __table_args__ = (
        UniqueConstraint("organization_id", "owner_name", name="uq_baseline_org_owner"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), index=True, nullable=False,
    )
    owner_name: Mapped[str] = mapped_column(String(120), index=True, nullable=False)

    #: Saa za kawaida za login/logout (mfano: {"start": 7, "end": 19})
    normal_hours: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Majina ya programu yanayotumika mara nyingi
    normal_processes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Domain zinazotembelewa mara nyingi
    normal_domains: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Wastani wa data inayodownloadwa kwa siku (bytes)
    avg_daily_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    #: Idadi ya wastani ya connections kwa siku
    avg_daily_connections: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Je, baseline iko tayari?
    ready: Mapped[bool] = mapped_column(default=False, nullable=False)
    #: Tarehe ya mwisho ya kusasisha
    last_refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    def __repr__(self) -> str:
        return f"<UserBaseline {self.owner_name} ready={self.ready}>"


class UserAnomaly(UUIDMixin, TimestampMixin, Base):
    """Anomaly moja iliyogunduliwa kwa mtumiaji."""

    __tablename__ = "user_anomalies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), index=True, nullable=False,
    )
    owner_name: Mapped[str] = mapped_column(String(120), index=True, nullable=False)

    #: Aina ya anomaly: login_time, new_domain, data_spike, lateral_movement,
    #: privilege_escalation, new_process, impossible_travel, etc.
    anomaly_type: Mapped[str] = mapped_column(String(48), index=True, nullable=False)
    #: low, medium, high, critical
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    #: Alama ya hatari (0-100)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Maelezo ya anomaly kwa binadamu
    description: Mapped[str] = mapped_column(Text, nullable=False)
    #: Data ya ziada (JSON): ip, domain, process, etc.
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Je, mtumiaji ameshathibitisha?
    status: Mapped[str] = mapped_column(
        String(24), default="open", index=True, nullable=False,
    )
    #: Kifaa kilichohusika
    device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    def __repr__(self) -> str:
        return f"<UserAnomaly {self.owner_name} {self.anomaly_type} {self.severity}>"


class UserRiskScore(UUIDMixin, TimestampMixin, Base):
    """Jumla ya hatari kwa mtumiaji."""

    __tablename__ = "user_risk_scores"
    __table_args__ = (
        UniqueConstraint("organization_id", "owner_name", name="uq_risk_org_owner"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), index=True, nullable=False,
    )
    owner_name: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    #: Jumla ya hatari ya sasa (0-100+)
    current_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Score ya awali (kwa mtindo)
    previous_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: up, down, stable
    trend: Mapped[str] = mapped_column(String(8), default="stable", nullable=False)
    #: Jumla ya anomalies zilizofunguliwa
    open_anomalies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Jumla ya anomalies zote
    total_anomalies: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Tarehe ya mwisho ya kusasisha
    last_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    def __repr__(self) -> str:
        return f"<UserRiskScore {self.owner_name} score={self.current_score}>"
