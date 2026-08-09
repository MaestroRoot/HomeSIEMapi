"""Adapter ya payment gateway.

Kuna implementations mbili:

* `ManualGateway` — hakuna mtandao unaopigwa; inarekodi nia ya kulipa kama
  "processing" na owner/admin athibitishe baadaye. Fallback ikiwa ClickPesa
  haijawekwa.
* `ClickPesaGateway` — inaunganisha na ClickPesa (Tanzania). Kwa mobile money
  inatumia USSD-PUSH: mteja anapata prompt kwenye simu, anaingiza PIN. Malipo
  ni ya asynchronous — hukamilika kupitia webhook (`confirm_payment`).

`get_gateway()` inachagua ClickPesa ikiwa credentials zipo (`settings.clickpesa_ready`),
la sivyo ManualGateway. Endpoints hazibadiliki.

MUHIMU: `charge()` haihifadhi KAMWE namba kamili ya card. Inayorudi ni
`GatewayResult` yenye reference pekee.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import PaymentChannel, PaymentMethod, PaymentStatus

logger = get_logger(__name__)

_TIMEOUT = 20.0

CHANNEL_LABELS: dict[PaymentChannel, str] = {
    PaymentChannel.YAS_MIX: "Yas Mix",
    PaymentChannel.MPESA: "M-Pesa",
    PaymentChannel.HALOPESA: "HaloPesa",
    PaymentChannel.AIRTEL_MONEY: "Airtel Money",
    PaymentChannel.CARD: "Bank card",
    PaymentChannel.PAYPAL: "PayPal",
}


def new_reference() -> str:
    """Reference ya kipekee. Ni alphanumeric PEKEE (bila '-') kwa sababu
    ClickPesa `orderReference` hairuhusu herufi nyingine."""
    stamp = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
    return f"HS{stamp}{secrets.token_hex(3).upper()}"


def normalize_msisdn(msisdn: str | None) -> str | None:
    """Weka namba katika umbo la ClickPesa: 255XXXXXXXXX (bila +, bila 0)."""
    if not msisdn:
        return None
    digits = re.sub(r"\D", "", msisdn)
    if digits.startswith("255"):
        return digits
    if digits.startswith("0") and len(digits) == 10:
        return "255" + digits[1:]
    if len(digits) == 9:  # 7XXXXXXXX
        return "255" + digits
    return digits or None


@dataclass(frozen=True)
class GatewayResult:
    status: PaymentStatus
    provider_reference: str | None
    instruction: str
    failure_reason: str | None = None


def _map_status(raw: str | None) -> PaymentStatus:
    s = (raw or "").upper()
    if s in ("SUCCESS", "SETTLED"):
        return PaymentStatus.SUCCEEDED
    if s == "FAILED":
        return PaymentStatus.FAILED
    return PaymentStatus.PROCESSING  # PROCESSING / PENDING / kingine


class ManualGateway:
    """Hakuna mtandao unaopigwa. Inarekodi nia ya kulipa pekee."""

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
    ) -> GatewayResult:
        label = CHANNEL_LABELS[channel]
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


class ClickPesaGateway:
    """Gateway halisi ya ClickPesa (USSD-PUSH kwa mobile money)."""

    name = "clickpesa"

    def __init__(self) -> None:
        self._base = settings.clickpesa_base_url.rstrip("/")
        self._client_id = settings.clickpesa_client_id or ""
        self._api_key = settings.clickpesa_api_key or ""

    async def _token(self, http: httpx.AsyncClient) -> str:
        """Pata Bearer token (halali saa 1). Inarudisha string yenye 'Bearer '."""
        r = await http.post(
            f"{self._base}/third-parties/generate-token",
            headers={"client-id": self._client_id, "api-key": self._api_key},
        )
        r.raise_for_status()
        data = r.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"ClickPesa haijatoa token: {data}")
        return token  # tayari ina 'Bearer '

    async def charge(
        self,
        *,
        reference: str,
        amount_tzs: int,
        method: PaymentMethod,
        channel: PaymentChannel,
        msisdn: str | None = None,
        card_last4: str | None = None,
    ) -> GatewayResult:
        # Card kupitia ClickPesa ni hosted-checkout tofauti (haijaunganishwa
        # bado); irudishe kama manual ili isivunje flow.
        if method is not PaymentMethod.MOBILE_MONEY:
            return GatewayResult(
                status=PaymentStatus.PROCESSING,
                provider_reference=None,
                instruction=(
                    f"A TSh {amount_tzs:,} card payment was recorded (ref {reference}). "
                    "Card payments are confirmed manually for now."
                ),
            )

        phone = normalize_msisdn(msisdn)
        if not phone:
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction="A valid mobile-money number is required.",
                failure_reason="missing_or_invalid_msisdn",
            )

        body = {
            "amount": str(amount_tzs),
            "currency": "TZS",
            "orderReference": reference,
            "phoneNumber": phone,
        }
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
                token = await self._token(http)
                headers = {"Authorization": token}
                # Preview ni best-effort (inathibitisha channel inapatikana).
                try:
                    await http.post(
                        f"{self._base}/third-parties/payments/preview-ussd-push-request",
                        json=body,
                        headers=headers,
                    )
                except httpx.HTTPError:
                    pass
                r = await http.post(
                    f"{self._base}/third-parties/payments/initiate-ussd-push-request",
                    json=body,
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            logger.error("ClickPesa initiate imeshindwa: ref=%s err=%s", reference, exc)
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction="We could not reach the payment provider. Please try again.",
                failure_reason="clickpesa_unreachable",
            )

        if r.status_code >= 400:
            detail = _extract_message(r)
            logger.warning("ClickPesa initiate %s: ref=%s %s", r.status_code, reference, detail)
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction=f"The payment could not be started: {detail}",
                failure_reason=detail[:200],
            )

        data = r.json()
        status = _map_status(data.get("status"))
        label = CHANNEL_LABELS[channel]
        instruction = (
            f"Check your phone {phone}: approve the {label} prompt and enter your PIN to pay "
            f"TSh {amount_tzs:,}. Reference: {reference}."
        )
        logger.info(
            "ClickPesa USSD-push: ref=%s provider_id=%s status=%s", reference, data.get("id"), status.value
        )
        return GatewayResult(
            status=status, provider_reference=data.get("id"), instruction=instruction
        )

    async def verify_status(self, order_reference: str) -> PaymentStatus | None:
        """Uliza ClickPesa status HALISI ya malipo (webhook haiaminiwi peke yake)."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
                token = await self._token(http)
                r = await http.get(
                    f"{self._base}/third-parties/payments/{order_reference}",
                    headers={"Authorization": token},
                )
        except httpx.HTTPError as exc:
            logger.error("ClickPesa verify imeshindwa: ref=%s err=%s", order_reference, exc)
            return None
        if r.status_code >= 400:
            return None
        payload = r.json()
        rows = payload if isinstance(payload, list) else [payload]
        statuses = {(_row.get("status") or "").upper() for _row in rows if isinstance(_row, dict)}
        if statuses & {"SUCCESS", "SETTLED"}:
            return PaymentStatus.SUCCEEDED
        if "FAILED" in statuses and not (statuses - {"FAILED"}):
            return PaymentStatus.FAILED
        if statuses:
            return PaymentStatus.PROCESSING
        return None


class PayPalGateway:
    """Gateway ya PayPal REST API. Ina-create order na kurejesha approval URL."""

    name = "paypal"

    def __init__(self) -> None:
        self._client_id = settings.paypal_client_id or ""
        self._client_secret = settings.paypal_client_secret or ""
        self._mode = settings.paypal_mode
        self._base = "https://api-m.paypal.com" if self._mode == "live" else "https://api-m.sandbox.paypal.com"

    async def _token(self, http: httpx.AsyncClient) -> str:
        """Pata OAuth2 access token (inaisha baada ya saa 1)."""
        import base64
        creds = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
        r = await http.post(
            f"{self._base}/v1/oauth2/token",
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/x-www-form-urlencoded"},
            content="grant_type=client_credentials",
        )
        r.raise_for_status()
        return r.json()["access_token"]

    async def create_order(
        self,
        *,
        reference: str,
        amount_tzs: int,
        return_url: str,
        cancel_url: str,
    ) -> dict:
        """Create PayPal order na kurudisha {id, approve_url}.

        PayPal haitumii TZS — tunaconvert kwenda USD kwa kiwango cha soko
        (TSh 2,550 = $1 USD takriban).
        """
        TZS_PER_USD = 2550
        amount_usd = round(amount_tzs / TZS_PER_USD, 2)
        if amount_usd < 1:
            amount_usd = 1.00

        token = await self._token(httpx.AsyncClient(timeout=_TIMEOUT))
        r = await httpx.AsyncClient(timeout=_TIMEOUT).post(
            f"{self._base}/v2/checkout/orders",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "intent": "CAPTURE",
                "purchase_units": [{
                    "reference_id": reference,
                    "amount": {
                        "currency_code": "USD",
                        "value": f"{amount_usd:.2f}",
                    },
                    "description": f"HomeSIEM subscription — TSh {amount_tzs:,} (≈${amount_usd:.2f} USD)",
                }],
                "application_context": {
                    "brand_name": "HomeSIEM",
                    "landing_page": "BILLING",
                    "shipping_preference": "NO_SHIPPING",
                    "return_url": return_url,
                    "cancel_url": cancel_url,
                },
            },
        )
        r.raise_for_status()
        data = r.json()
        approve_url = next(
            (link["href"] for link in data.get("links", []) if link.get("rel") == "approve"),
            "",
        )
        return {"id": data["id"], "approve_url": approve_url}

    async def capture_order(self, order_id: str) -> GatewayResult:
        """Capture order baada ya user ku-approve."""
        token = await self._token(httpx.AsyncClient(timeout=_TIMEOUT))
        r = await httpx.AsyncClient(timeout=_TIMEOUT).post(
            f"{self._base}/v2/checkout/orders/{order_id}/capture",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        if r.status_code >= 400:
            detail = _extract_message(r)
            logger.warning("PayPal capture %s: order_id=%s %s", r.status_code, order_id, detail)
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=order_id,
                instruction=f"PayPal payment could not be captured: {detail}",
                failure_reason=detail[:200],
            )
        data = r.json()
        status_str = data.get("status", "")
        if status_str == "COMPLETED":
            return GatewayResult(
                status=PaymentStatus.SUCCEEDED,
                provider_reference=order_id,
                instruction="PayPal payment captured successfully.",
            )
        return GatewayResult(
            status=PaymentStatus.PROCESSING,
            provider_reference=order_id,
            instruction=f"PayPal order status: {status_str}",
        )

    async def verify_status(self, order_id: str) -> PaymentStatus | None:
        """Angalia PayPal order status."""
        try:
            token = await self._token(httpx.AsyncClient(timeout=_TIMEOUT))
            r = await httpx.AsyncClient(timeout=_TIMEOUT).get(
                f"{self._base}/v2/checkout/orders/{order_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError:
            return None
        if r.status_code >= 400:
            return None
        status_str = r.json().get("status", "")
        if status_str == "COMPLETED":
            return PaymentStatus.SUCCEEDED
        if status_str in ("VOIDED", "PAYER_ACTION_REQUIRED"):
            return PaymentStatus.FAILED
        return PaymentStatus.PROCESSING


def _extract_message(r: httpx.Response) -> str:
    try:
        data = r.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("error") or data)
        return str(data)
    except ValueError:
        return r.text[:200] or f"HTTP {r.status_code}"


def get_gateway(method: PaymentMethod | None = None) -> ManualGateway | ClickPesaGateway | PayPalGateway:
    """Sehemu moja ya kuchagua gateway kulingana na njia ya malipo.

    PayPal inachaguliwa tu ikiwa `method` ni PAYPAL. ClickPesa kwa mobile money
    ikiwa credentials zipo. Manual ni fallback.
    """
    if method is PaymentMethod.PAYPAL and settings.paypal_ready:
        return PayPalGateway()
    if settings.clickpesa_ready:
        return ClickPesaGateway()
    return ManualGateway()
