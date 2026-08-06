"""Groq AI (chat completions, OpenAI-compatible API).

Groq inatoa API inayofanana na OpenAI. Tunatumia `httpx.AsyncClient` (mtindo
ule ule wa `email.py`/`threatintel.py`), si SDK, ili tubaki async na wepesi.
"""

from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.errors import ServiceUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

_URL = "https://api.groq.com/openai/v1/chat/completions"
_TIMEOUT = 45.0


async def chat(
    *,
    system: str,
    messages: list[dict[str, str]],
    temperature: float = 0.3,
    max_tokens: int = 1024,
) -> str:
    """Tuma mazungumzo kwa Groq, rudisha maandishi ya jibu."""
    if not settings.groq_api_key:
        raise ServiceUnavailableError(
            "AI is not configured (GROQ_API_KEY is missing).", code="ai_unconfigured"
        )

    payload = {
        "model": settings.groq_model,
        "messages": [{"role": "system", "content": system}, *messages],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
            resp = await http.post(
                _URL,
                json=payload,
                headers={"Authorization": f"Bearer {settings.groq_api_key}"},
            )
    except httpx.HTTPError as exc:
        logger.error("Groq haipatikani: %s", exc)
        raise ServiceUnavailableError("The AI service is unreachable.", code="ai_unreachable") from exc

    if resp.status_code >= 300:
        logger.error("Groq imekataa (%s): %s", resp.status_code, resp.text[:300])
        raise ServiceUnavailableError("The AI service returned an error.", code="ai_error")

    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        logger.error("Groq umbo lisilotarajiwa: %s", str(data)[:300])
        raise ServiceUnavailableError("The AI service returned an unexpected response.", code="ai_bad_response") from exc
