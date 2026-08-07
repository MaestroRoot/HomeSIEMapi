"""Katalogi ya vifurushi: bei, huduma na mipaka.

Hii ndiyo chanzo pekee cha ukweli kuhusu nani anapata nini. Frontend ina nakala
yake (`frontend/src/lib/plans.ts`) kwa ajili ya kuonyesha UI, lakini backend
KAMWE haiamini kile client anachosema kuhusu kifurushi chake, `plan` inasomwa
kutoka row ya `users`/`organizations`.

Bei ni senti ZERO, tunahifadhi TSHS nzima kwa sababu shilingi haina senti
zinazotumika kwenye malipo ya mtandaoni hapa.
"""

from dataclasses import dataclass, field

from app.models.enums import PLAN_RANK, Plan

CURRENCY = "TZS"


@dataclass(frozen=True)
class PlanLimits:
    """0 maana yake hakuna kikomo."""

    devices: int
    retention_days: int
    ai_requests_per_day: int
    seats: int


@dataclass(frozen=True)
class PlanSpec:
    plan: Plan
    label: str
    tagline: str
    price_tzs: int
    limits: PlanLimits
    #: module ids kutoka `frontend/src/lib/modules.ts`
    modules: tuple[str, ...]
    highlights: tuple[str, ...] = field(default_factory=tuple)
    recommended: bool = False


# --- Huduma zinavyoongezeka kifurushi hadi kifurushi -----------------------

_FREE_MODULES = (
    "overview",
    "devices",
    "search",
    "alerts",
    "score",
    "ueba",
    "compliance",
    "account",
)

_HOME_ADDS = (
    "agents",
    "logs",
    "detection",
    "ioc",
    "timeline",
    "visualization",
    "alert-integrations",
)

_PRO_ADDS = (
    "pcap",
    "ai-logs",
    "ai-packets",
    "assistant",
    "incidents",
    "rules",
    "intel",
    "reports",
    "ai-rules",
    "network-graph",
    "attack-chain",
    "geo-map",
    "coverage",
    "runbooks",
    "log-parsers",
)

_BUSINESS_ADDS = (
    "forensics",
    "vulnerabilities",
    "inventory",
    "investigation",
)

_HOME_MODULES = _FREE_MODULES + _HOME_ADDS
_PRO_MODULES = _HOME_MODULES + _PRO_ADDS
_BUSINESS_MODULES = _PRO_MODULES + _BUSINESS_ADDS


PLAN_CATALOGUE: dict[Plan, PlanSpec] = {
    Plan.FREE: PlanSpec(
        plan=Plan.FREE,
        label="Free",
        tagline="Basic visibility for your home network.",
        price_tzs=0,
        limits=PlanLimits(devices=2, retention_days=1, ai_requests_per_day=0, seats=1),
        modules=_FREE_MODULES,
        highlights=(
            "2 devices",
            "24 hours of log history",
            "Core alerting and Security Score",
            "Behavior Analytics (UEBA)",
            "Compliance Center",
        ),
    ),
    Plan.HOME: PlanSpec(
        plan=Plan.HOME,
        label="Home",
        tagline="Full monitoring for your household.",
        price_tzs=15_000,
        limits=PlanLimits(devices=5, retention_days=7, ai_requests_per_day=50, seats=2),
        modules=_HOME_MODULES,
        highlights=(
            "5 devices",
            "7 days of retention",
            "Threat Detection engine",
            "IOC Scanner, Timeline, Visualization",
            "Alert Integrations (Slack, email, webhook)",
        ),
    ),
    Plan.PRO: PlanSpec(
        plan=Plan.PRO,
        label="Pro",
        tagline="Advanced investigation and response tools.",
        price_tzs=50_000,
        limits=PlanLimits(devices=25, retention_days=30, ai_requests_per_day=500, seats=5),
        modules=_PRO_MODULES,
        highlights=(
            "25 devices",
            "30 days of retention",
            "AI Log Explorer and Packet Analysis",
            "PCAP upload and offline analysis",
            "Incidents, Rule Engine, Threat Intel",
            "Network Graph, Attack Chain, Geo Map",
            "Runbooks, Log Parsers, Detection Coverage",
            "PDF, Excel and CSV reports",
        ),
        recommended=True,
    ),
    Plan.BUSINESS: PlanSpec(
        plan=Plan.BUSINESS,
        label="Business",
        tagline="Enterprise forensics, vulnerabilities and inventory.",
        price_tzs=150_000,
        limits=PlanLimits(devices=0, retention_days=365, ai_requests_per_day=0, seats=25),
        modules=_BUSINESS_MODULES,
        highlights=(
            "Unlimited devices",
            "A full year of retention",
            "Forensics deep-dive",
            "Vulnerability Scanner",
            "Network Inventory",
            "AI Investigation",
            "25 seats",
        ),
    ),
}

#: Mpangilio wa kuonyesha kwenye ukurasa wa subscriptions.
PLAN_ORDER: tuple[Plan, ...] = (Plan.FREE, Plan.HOME, Plan.PRO, Plan.BUSINESS)

#: Kifurushi anachoshuka nacho mtu trial ikiisha bila malipo.
DEFAULT_PLAN = Plan.FREE

#: Kila anayejisajili anapewa Business bure kwa muda huu.
TRIAL_PLAN = Plan.BUSINESS
TRIAL_DAYS = 30


def spec_for(plan: Plan) -> PlanSpec:
    return PLAN_CATALOGUE[plan]


def price_of(plan: Plan) -> int:
    return PLAN_CATALOGUE[plan].price_tzs


def modules_for(plan: Plan) -> tuple[str, ...]:
    return PLAN_CATALOGUE[plan].modules


def plan_allows(plan: Plan, module_id: str) -> bool:
    return module_id in PLAN_CATALOGUE[plan].modules


def is_upgrade(current: Plan, target: Plan) -> bool:
    return PLAN_RANK[target] > PLAN_RANK[current]


def paid_plans() -> tuple[Plan, ...]:
    return tuple(p for p in PLAN_ORDER if PLAN_CATALOGUE[p].price_tzs > 0)
