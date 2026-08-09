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
    PaymentChannel.PESAPAL: "PesaPal",
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
        card_brand: str | None = None,
        card_number: str | None = None,
        card_holder: str | None = None,
        card_expiry_month: int | None = None,
        card_expiry_year: int | None = None,
        card_cvv: str | None = None,
        return_url: str | None = None,
        cancel_url: str | None = None,
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
        card_brand: str | None = None,
        card_number: str | None = None,
        card_holder: str | None = None,
        card_expiry_month: int | None = None,
        card_expiry_year: int | None = None,
        card_cvv: str | None = None,
        return_url: str | None = None,
        cancel_url: str | None = None,
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


class PesaPalGateway:
    """Gateway ya PesaPal API 3.0. Inashughulikia card payments (Visa, Mastercard, AMEX)
    na mobile money (M-Pesa, Tigo Pesa, Airtel Money).
    
    PesaPal ni rahisi: 
    1. Authenticate → pata access token
    2. SubmitOrderRequest → pata redirect URL
    3. Mteja anaenda kwenye redirect URL, ana-chagua payment method
    4. PesaPal inatuma IPN (Instant Payment Notification)
    5. Sisi tunahakiki status na kurejesha result
    
    USD currency: PesaPal inashughulikia USD, hivyo tunaconvert TZS → USD.
    """

    name = "pesapal"

    def __init__(self) -> None:
        self._consumer_key = settings.pesapal_consumer_key or ""
        self._consumer_secret = settings.pesapal_consumer_secret or ""
        self._mode = settings.pesapal_mode
        self._base = "https://pay.pesapal.com/v3" if self._mode == "live" else "https://cybqa.pesapal.com/pesapalv3"
        self._ipn_url = settings.pesapal_ipn_url or ""
        self._ipn_id = settings.pesapal_ipn_id or ""

    async def _token(self, http: httpx.AsyncClient) -> str:
        """Pata PesaPal access token (inaisha baada ya dakika 5)."""
        r = await http.post(
            f"{self._base}/api/Auth/RequestToken",
            json={
                "consumer_key": self._consumer_key,
                "consumer_secret": self._consumer_secret,
            },
        )
        r.raise_for_status()
        data = r.json()
        token = data.get("token")
        if not token:
            raise RuntimeError(f"PesaPal haijatoa token: {data}")
        return token

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
        return_url: str | None = None,
        cancel_url: str | None = None,
    ) -> GatewayResult:
        """PesaPal card payment — ina-create order na kurejesha redirect URL.
        
        PesaPal inashughulikia card payments moja kwa moja (Visa, Mastercard, AMEX).
        Mteja anaenda kwenye redirect URL, ana-chagua card, na anaingiza details.
        """
        if method not in (PaymentMethod.BANK_CARD, PaymentMethod.PESAPAL):
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction="PesaPal currently only supports card payments.",
                failure_reason="unsupported_method",
            )

        TZS_PER_USD = 2550
        amount_usd = max(1.00, round(amount_tzs / TZS_PER_USD, 2))

        token = await self._token(httpx.AsyncClient(timeout=_TIMEOUT))

        body = {
            "id": reference[:50],  # PesaPal max 50 chars
            "currency": "USD",
            "amount": amount_usd,
            "description": f"HomeSIEM subscription — TSh {amount_tzs:,} (≈${amount_usd:.2f} USD)",
            "callback_url": return_url or self._ipn_url,
            "redirect_mode": "TOP_WINDOW",
            "notification_id": self._ipn_id,  # IPN ID from registration
            "branch": "HomeSIEM",
            "billing_address": {
                "email_address": "",  # Will be filled from user data
                "phone_number": msisdn or "",
                "country_code": "TZ",
                "first_name": card_holder or "",
                "last_name": "",
                "line_1": "",
                "city": "",
                "state": "",
                "postal_code": "",
                "zip_code": "",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
                r = await http.post(
                    f"{self._base}/api/Transactions/SubmitOrderRequest",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    json=body,
                )
        except httpx.HTTPError as exc:
            logger.error("PesaPal charge imeshindwa: ref=%s err=%s", reference, exc)
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction="Could not reach PesaPal. Please try again.",
                failure_reason="pesapal_unreachable",
            )

        if r.status_code >= 400:
            detail = _extract_message(r)
            logger.warning("PesaPal charge %s: ref=%s %s", r.status_code, reference, detail)
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=None,
                instruction=f"Card payment failed: {detail}",
                failure_reason=detail[:200],
            )

        data = r.json()
        logger.info("PesaPal response: %s", data)
        order_tracking_id = data.get("order_tracking_id")
        redirect_url = data.get("redirect_url")

        if not redirect_url:
            return GatewayResult(
                status=PaymentStatus.FAILED,
                provider_reference=order_tracking_id,
                instruction="PesaPal did not return a payment URL.",
                failure_reason="no_redirect_url",
            )

        logger.info(
            "PesaPal order created: ref=%s order_id=%s", reference, order_tracking_id
        )
        return GatewayResult(
            status=PaymentStatus.PROCESSING,
            provider_reference=order_tracking_id,
            instruction=f"redirect:{redirect_url}",
        )

    async def verify_status(self, order_tracking_id: str) -> PaymentStatus | None:
        """Angalia PesaPal order status."""
        try:
            token = await self._token(httpx.AsyncClient(timeout=_TIMEOUT))
            r = await httpx.AsyncClient(timeout=_TIMEOUT).get(
                f"{self._base}/api/Transactions/GetTransactionStatus",
                params={"orderTrackingId": order_tracking_id},
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError:
            return None
        if r.status_code >= 400:
            return None
        data = r.json()
        status_code = data.get("status_code")
        # PesaPal status codes: 0=INVALID, 1=COMPLETED, 2=FAILED, 3=REVERSED
        if status_code == 1:
            return PaymentStatus.SUCCEEDED
        if status_code in (2, 3):
            return PaymentStatus.FAILED
        if status_code == 0:
            return PaymentStatus.CANCELLED
        return PaymentStatus.PROCESSING


def _extract_message(r: httpx.Response) -> str:
    try:
        data = r.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("error") or data)
        return str(data)
    except ValueError:
        return r.text[:200] or f"HTTP {r.status_code}"


def get_gateway(method: PaymentMethod | None = None) -> ManualGateway | ClickPesaGateway | PesaPalGateway:
    """Sehemu moja ya kuchagua gateway kulingana na njia ya malipo.

    PesaPal inachaguliwa kwa BANK_CARD na PESAPAL (card payments).
    ClickPesa kwa mobile money.
    Manual ni fallback.
    """
    if method in (PaymentMethod.BANK_CARD, PaymentMethod.PESAPAL) and settings.pesapal_ready:
        return PesaPalGateway()
    if settings.clickpesa_ready:
        return ClickPesaGateway()
    return ManualGateway()
