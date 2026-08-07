"""Schemas za UEBA (User and Entity Behavior Analytics)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel

AnomalyStatus = Literal["open", "investigating", "resolved", "false_positive"]
AnomalySeverity = Literal["low", "medium", "high", "critical"]
RiskTrend = Literal["up", "down", "stable"]


# --- Overview --------------------------------------------------------------


class UebaOverview(CamelModel):
    """Muhtasari wa UEBA kwa dashboard."""

    total_users: int
    monitored_users: int
    total_anomalies_today: int
    critical_users: int
    high_users: int
    baselines_ready: int
    baselines_pending: int


# --- User risk scores -----------------------------------------------------


class UserRiskRead(CamelModel):
    """Risk score ya mtumiaji mmoja."""

    owner_name: str
    current_score: int
    previous_score: int
    trend: RiskTrend
    open_anomalies: int
    total_anomalies: int
    last_updated_at: datetime | None = None

    @field_serializer("owner_name")
    def _name(self, value: str) -> str:
        return value


class UserRiskList(CamelModel):
    items: list[UserRiskRead]
    total: int


# --- All device users ------------------------------------------------------


class DeviceUserRead(CamelModel):
    """Mtumiaji wa device, pamoja na risk score iwapo ipo."""

    owner_name: str
    device_count: int
    has_baseline: bool
    current_score: int = 0
    previous_score: int = 0
    trend: RiskTrend = "stable"
    open_anomalies: int = 0
    total_anomalies: int = 0
    last_updated_at: datetime | None = None

    @field_serializer("owner_name")
    def _name(self, value: str) -> str:
        return value


class DeviceUserList(CamelModel):
    items: list[DeviceUserRead]
    total: int


# --- Anomalies ------------------------------------------------------------


class AnomalyRead(CamelModel):
    """Anomaly moja."""

    id: uuid.UUID
    owner_name: str
    anomaly_type: str
    severity: AnomalySeverity
    risk_score: int
    description: str
    evidence: dict
    status: AnomalyStatus
    device_name: str | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class AnomalyList(CamelModel):
    items: list[AnomalyRead]
    total: int


# --- User detail ----------------------------------------------------------


class UserBaselineRead(CamelModel):
    """Baseline ya mtumiaji."""

    owner_name: str
    normal_hours: dict
    normal_processes: list
    normal_domains: list
    avg_daily_bytes: int
    avg_daily_connections: int
    ready: bool
    last_refreshed_at: datetime | None = None


class UserTimelineEntry(CamelModel):
    """Kitu kimoja kwenye timeline ya mtumiaji."""

    time: datetime
    activity_type: str
    description: str
    severity: str
    source: str
    details: dict = {}


class UserDetail(CamelModel):
    """Detail za mtumiaji kwa UEBA."""

    owner_name: str
    risk_score: UserRiskRead
    baseline: UserBaselineRead | None = None
    recent_anomalies: list[AnomalyRead]
    timeline: list[UserTimelineEntry]
    devices: list[str]


# --- Anomaly update -------------------------------------------------------


class AnomalyUpdate(CamelModel):
    """Badilisha status ya anomaly."""

    status: AnomalyStatus
