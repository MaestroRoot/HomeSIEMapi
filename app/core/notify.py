"""Kutuma arifa kwa channels za nje (Slack/Discord/email/webhook/PagerDuty).

Webhooks zinatumwa kwa `httpx.AsyncClient`; email inapita kwenye Brevo
(`app.core.email`). Kila function inarudisha bool, kushindwa kutuma
hakuangushi ingest.
"""

from __future__ import annotations

import httpx

from app.core.email import send_email
from app.core.logging import get_logger

logger = get_logger(__name__)

_TIMEOUT = 10.0

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_meets(event_severity: str, min_severity: str) -> bool:
    return _SEVERITY_RANK.get(event_severity, 0) >= _SEVERITY_RANK.get(min_severity, 0)


async def _post_json(url: str, payload: dict) -> bool:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
            resp = await http.post(url, json=payload)
        if resp.status_code >= 300:
            logger.warning("Webhook imekataa (%s): %s", resp.status_code, resp.text[:200])
            return False
        return True
    except httpx.HTTPError as exc:
        logger.warning("Webhook haipatikani: %s", exc)
        return False


async def send_alert(*, ch_type: str, target: str, subject: str, message: str) -> bool:
    """Tuma arifa kwa channel moja. `message` ni maandishi wazi."""
    if ch_type == "slack":
        return await _post_json(target, {"text": f"*{subject}*\n{message}"})
    if ch_type == "discord":
        return await _post_json(target, {"content": f"**{subject}**\n{message}"})
    if ch_type == "pagerduty":
        # Events API v2: target ni routing key.
        return await _post_json(
            "https://events.pagerduty.com/v2/enqueue",
            {
                "routing_key": target,
                "event_action": "trigger",
                "payload": {"summary": subject, "source": "HomeSIEM", "severity": "warning", "custom_details": {"message": message}},
            },
        )
    if ch_type == "webhook":
        return await _post_json(target, {"subject": subject, "message": message, "source": "HomeSIEM"})
    if ch_type == "email":
        html = f"<h2 style='font-size:16px;color:#0f172a'>{subject}</h2><pre style='white-space:pre-wrap;font-family:inherit;color:#334155'>{message}</pre>"
        return await send_email(to_email=target, to_name=None, subject=subject, html=html, text=message, tags=["alert"])
    logger.warning("Aina ya channel isiyojulikana: %s", ch_type)
    return False
