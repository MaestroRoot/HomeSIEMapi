"""Schemas za takwimu zilizokusanywa kutoka events (Overview, Visualization)."""

from __future__ import annotations

from app.schemas.common import CamelModel
from app.schemas.intel import Verdict


class VerdictBreakdown(CamelModel):
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    unknown: int = 0


class TopDomain(CamelModel):
    name: str
    count: int
    flagged: bool


class TopTalker(CamelModel):
    label: str
    count: int


class SuspiciousIndicator(CamelModel):
    indicator: str
    verdict: Verdict
    country: str | None = None
    pulse_count: int = 0
    count: int


class TimeBucket(CamelModel):
    t: str
    events: int
    flagged: int


class CountryCount(CamelModel):
    name: str
    count: int


class ScoreIssue(CamelModel):
    title: str
    impact: int
    severity: str
    detail: str
    fix: str


class SecurityScore(CamelModel):
    score: int
    grade: str
    summary: str
    issues: list[ScoreIssue] = []


class StatsOverview(CamelModel):
    total_events: int = 0
    events24h: int = 0
    flagged: int = 0
    unique_domains: int = 0
    unique_external_ips: int = 0
    total_devices: int = 0
    active_devices: int = 0
    by_verdict: VerdictBreakdown = VerdictBreakdown()
    top_domains: list[TopDomain] = []
    top_talkers: list[TopTalker] = []
    suspicious: list[SuspiciousIndicator] = []
    over_time: list[TimeBucket] = []
    by_country: list[CountryCount] = []
