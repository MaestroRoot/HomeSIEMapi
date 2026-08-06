"""AI endpoints (Groq): assistant, analyzer, rule generator.

Zinaunganisha `app/core/ai.py` na data halisi ya org ili majibu yategemee
matukio ya mtumiaji, sio maandishi ya jumla.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import Field

from app.api.deps import CurrentUser, DbSession
from app.core import ai
from app.crud import monitoring as mon_crud
from app.crud import stats as stats_crud
from app.schemas.common import CamelModel
from app.schemas.stats import StatsOverview

router = APIRouter(prefix="/ai", tags=["ai"])


# --- schemas --------------------------------------------------------------


class ChatMessage(CamelModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


class ChatRequest(CamelModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)


class AiText(CamelModel):
    reply: str


class AnalyzeRequest(CamelModel):
    kind: Literal["log", "capture", "investigation"]
    content: str = Field(default="", max_length=20000)


class RuleRequest(CamelModel):
    description: str = Field(min_length=3, max_length=500)


# --- helpers --------------------------------------------------------------


def _context_line(s: StatsOverview) -> str:
    top = ", ".join(f"{d.name}({d.count})" for d in s.top_domains[:6]) or "none"
    susp = ", ".join(f"{i.indicator}[{i.verdict}]" for i in s.suspicious[:6]) or "none"
    return (
        f"Network snapshot: {s.total_events} events total, {s.events24h} in last 24h, "
        f"{s.flagged} flagged. Verdicts: malicious={s.by_verdict.malicious}, "
        f"suspicious={s.by_verdict.suspicious}, clean={s.by_verdict.clean}. "
        f"Devices: {s.active_devices}/{s.total_devices} active. "
        f"Top domains: {top}. Flagged indicators: {susp}."
    )


_ASSISTANT_SYSTEM = (
    "You are the security assistant inside HomeSIEM, a home network SIEM. You can see the "
    "user's live data (summarised below). Answer as a concise, practical security analyst. "
    "Be honest about limits: DNS/flow reputation catches contact with known-bad infrastructure, "
    "it does not read encrypted content. Never invent events that are not in the snapshot.\n\n"
)


# --- endpoints ------------------------------------------------------------


@router.post("/chat", response_model=AiText, summary="Ask the security assistant")
async def chat(payload: ChatRequest, user: CurrentUser, db: DbSession) -> AiText:
    stats = await stats_crud.overview(db, user.organization_id)
    system = _ASSISTANT_SYSTEM + _context_line(stats)
    messages = [{"role": m.role, "content": m.content} for m in payload.messages]
    reply = await ai.chat(system=system, messages=messages, temperature=0.4)
    return AiText(reply=reply)


@router.post("/analyze", response_model=AiText, summary="AI analysis of a log, capture or the network")
async def analyze(payload: AnalyzeRequest, user: CurrentUser, db: DbSession) -> AiText:
    content = payload.content.strip()

    if payload.kind == "log":
        system = (
            "You analyse security logs. Given raw log lines, explain what happened, build a short "
            "timeline, flag suspicious accounts, failed logins or anomalies, and recommend next steps. "
            "Be concrete and concise. If the input is not a log, say so."
        )
        user_msg = content or "(no log provided)"

    elif payload.kind == "capture":
        system = (
            "You analyse network capture summaries (DNS lookups, flows, enrichment verdicts). "
            "Explain in plain language what the traffic is, highlight anything suspicious, and give a "
            "confidence level. Do not invent packets not in the summary."
        )
        user_msg = content or "(no capture summary provided)"

    else:  # investigation, over the user's own recent flagged events
        rows, _ = await mon_crud.list_events(db, user.organization_id, limit=40, only_flagged=True)
        if not rows:
            return AiText(reply="There are no flagged events to investigate right now. That is the good case.")
        lines = [
            f"- {ev.created_at:%Y-%m-%d %H:%M} {name or ev.src_ip} {ev.kind} "
            f"{ev.domain or ev.dst_ip} verdict={ev.verdict} pulses={ev.pulse_count} "
            f"{ev.country or ''}"
            for ev, name in rows
        ]
        system = (
            "You are a SOC analyst writing a short investigation narrative from flagged events. "
            "Describe what the devices did, whether it looks like a real threat or likely noise, and "
            "what to do next. Give a confidence estimate. Be honest that OTX reputation is a lead, not proof."
        )
        user_msg = "Flagged events:\n" + "\n".join(lines)

    reply = await ai.chat(
        system=system, messages=[{"role": "user", "content": user_msg}], temperature=0.3, max_tokens=1200
    )
    return AiText(reply=reply)


@router.post("/generate-rule", response_model=AiText, summary="Generate a detection rule from a description")
async def generate_rule(payload: RuleRequest, user: CurrentUser) -> AiText:
    system = (
        "You generate detection rules for HomeSIEM. Output ONLY a JSON object with keys: "
        '"name" (short), "conditionType" (one of: verdict_is, domain_contains, country_is, '
        'pulse_count_gte), "value" (the value to match, e.g. \"malicious\", a domain substring, '
        'a country name, or a number), "severity" (critical|high|medium|low), and "action" '
        '(alert|log). No prose, no markdown fences, JSON only.'
    )
    reply = await ai.chat(
        system=system,
        messages=[{"role": "user", "content": payload.description}],
        temperature=0.1,
        max_tokens=300,
    )
    return AiText(reply=reply)
