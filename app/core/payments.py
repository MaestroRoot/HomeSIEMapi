"""Payment gateway adapter.

`ManualGateway` — records the intent; admin confirms later.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.models.enums import PaymentChannel, PaymentMethod, PaymentStatus

logger = get_logger(__name__)


CHANNEL_LABELS: dict[PaymentChannel, str] = {
    PaymentChannel.YAS_MIX: "Yas Mix",
    PaymentChannel.MPESA: "M-Pesa",
    PaymentChannel.HALOPESA: "HaloPesa",
    PaymentChannel.AIRTEL_MONEY: "Airtel Money",
    PaymentChannel.CARD: "Bank card",
}


def new_reference() -> str:
    stamp = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
    return f"HS{stamp}{secrets.token_hex(3).upper()}"


def normalize_msisdn(msisdn: str | None) -> str | None:
    if not msisdn:
        return None
    digits = re.sub(r"\D", "", msisdn)
    if digits.startswith("255"):
        return digits
    if digits.startswith("0") and len(digits) == 10:
        return "255" + digits[1:]
    if len(digits) == 9:
        return "255" + digits
    return digits or None


@dataclass(frozen=True)
class GatewayResult:
    status: PaymentStatus
    provider_reference: str | None
    instruction: str
    failure_reason: str | None = None


class ManualGateway:
    """No network call. Records payment intent only."""

    name = "manual"

    async def charge(
        self,
        *,
        reference: str,
        amount_tzs: int,
        method: PaymentMethod,
        channel: PaymentChannel,
        msisdn: str | None = None,
        card_last4: str | None = None,
        card_brand: str | None = None,
        card_number: str | None = None,
        card_holder: str | None = None,
        card_expiry_month: int | None = None,
        card_expiry_year: int | None = None,
        card_cvv: str | None = None,
    ) -> GatewayResult:
        label = CHANNEL_LABELS.get(channel, channel.value)
        if method is PaymentMethod.MOBILE_MONEY:
            instruction = (
                f"We have set up a TSh {amount_tzs:,} payment through {label} on {msisdn}. "
                f"You will get a confirmation prompt on your phone. Reference: {reference}."
            )
        else:
            instruction = (
                f"We have set up a TSh {amount_tzs:,} payment on the card ending {card_last4}. "
                f"Reference: {reference}."
            )
        logger.info("Malipo yameandaliwa (manual): ref=%s amount=%s", reference, amount_tzs)
        return GatewayResult(
            status=PaymentStatus.PROCESSING, provider_reference=None, instruction=instruction
        )


def get_gateway(method: PaymentMethod | None = None) -> ManualGateway:
    return ManualGateway()
