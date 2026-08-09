import re
import uuid
from datetime import datetime, timezone

from pydantic import Field, field_serializer, field_validator, model_validator

from app.models.enums import (
    CHANNELS_BY_METHOD,
    PaymentChannel,
    PaymentMethod,
    PaymentStatus,
    Plan,
    SubscriptionStatus,
)
from app.schemas.common import CamelModel

# 255XXXXXXXXX baada ya kusafisha. Tunakubali 0712..., +255712..., 255712...
_MSISDN_CLEAN = re.compile(r"[^\d]")
_TZ_MSISDN = re.compile(r"^255[67]\d{8}$")


def normalise_msisdn(raw: str) -> str:
    """Inarudisha namba katika umbo la 255XXXXXXXXX au inarusha ValueError."""
    digits = _MSISDN_CLEAN.sub("", raw or "")
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0"):
        digits = "255" + digits[1:]
    elif len(digits) == 9 and digits[0] in "67":
        digits = "255" + digits
    if not _TZ_MSISDN.match(digits):
        raise ValueError("That phone number is not valid. Use the form 0712345678.")
    return digits


class PlanLimitsRead(CamelModel):
    devices: int
    retention_days: int
    ai_requests_per_day: int
    seats: int


class PlanRead(CamelModel):
    """Kifurushi kimoja kama kinavyoonyeshwa kwenye ukurasa wa subscriptions."""

    plan: Plan
    label: str
    tagline: str
    price_tzs: int
    currency: str
    limits: PlanLimitsRead
    modules: list[str]
    highlights: list[str]
    recommended: bool


class PlanCatalogue(CamelModel):
    currency: str
    plans: list[PlanRead]


class SubscriptionRead(CamelModel):
    id: uuid.UUID
    plan: Plan
    status: SubscriptionStatus
    price_tzs: int
    currency: str
    started_at: datetime | None = None
    current_period_end: datetime | None = None
    trial_ends_at: datetime | None = None
    cancelled_at: datetime | None = None
    auto_renew: bool
    #: Siku zilizobaki za trial, zikizungushwa juu. None ikiwa hayuko kwenye trial.
    trial_days_left: int | None = None

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class PaymentRead(CamelModel):
    id: uuid.UUID
    plan: Plan
    amount_tzs: int
    currency: str
    method: PaymentMethod
    channel: PaymentChannel
    status: PaymentStatus
    msisdn: str | None = None
    card_last4: str | None = None
    card_brand: str | None = None
    reference: str
    provider_reference: str | None = None
    failure_reason: str | None = None
    paid_at: datetime | None = None
    created_at: datetime

    @field_serializer("id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class PaymentList(CamelModel):
    items: list[PaymentRead]
    total: int


class SubscriptionState(CamelModel):
    """Kila kitu ukurasa wa subscriptions unachohitaji katika request moja."""

    subscription: SubscriptionRead
    catalogue: PlanCatalogue
    modules: list[str]
    limits: PlanLimitsRead
    pending_payment: PaymentRead | None = None


class CardDetails(CamelModel):
    """Card inatumwa kwa gateway, HAIHIFADHIWI kwenye DB yetu.

    Backend inachukua tarakimu 4 za mwisho na brand pekee kabla ya kutupa
    namba nzima. Endpoint hii inahitaji HTTPS kwenye production.
    """

    number: str = Field(min_length=12, max_length=25)
    holder: str = Field(min_length=2, max_length=120)
    expiry_month: int = Field(ge=1, le=12)
    expiry_year: int = Field(ge=2024, le=2100)
    cvv: str = Field(min_length=3, max_length=4)

    @field_validator("number")
    @classmethod
    def _digits_only(cls, value: str) -> str:
        digits = _MSISDN_CLEAN.sub("", value)
        if not 12 <= len(digits) <= 19 or not _luhn_ok(digits):
            raise ValueError("That card number is not valid.")
        return digits

    @field_validator("cvv")
    @classmethod
    def _cvv_digits(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("The CVV must be digits only.")
        return value

    @model_validator(mode="after")
    def _not_expired(self) -> "CardDetails":
        today = datetime.now(timezone.utc).date()
        if (self.expiry_year, self.expiry_month) < (today.year, today.month):
            raise ValueError("That card has expired.")
        return self


def _luhn_ok(number: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_brand_of(number: str) -> str:
    if number.startswith("4"):
        return "Visa"
    if number[:2] in {"51", "52", "53", "54", "55"} or 2221 <= int(number[:4]) <= 2720:
        return "Mastercard"
    if number[:2] in {"34", "37"}:
        return "Amex"
    return "Card"


class CheckoutRequest(CamelModel):
    """Kuanzisha malipo ya kifurushi."""

    plan: Plan
    method: PaymentMethod
    channel: PaymentChannel
    #: Mobile money pekee.
    msisdn: str | None = None
    #: Card pekee.
    card: CardDetails | None = None
    #: PesaPal redirect URLs.
    return_url: str | None = None
    cancel_url: str | None = None

    @field_validator("msisdn")
    @classmethod
    def _check_msisdn(cls, value: str | None) -> str | None:
        return normalise_msisdn(value) if value else None

    @model_validator(mode="after")
    def _check_combination(self) -> "CheckoutRequest":
        if self.plan is Plan.FREE:
            raise ValueError("The Free plan is not something you pay for.")
        if self.channel not in CHANNELS_BY_METHOD[self.method]:
            raise ValueError(
                f"'{self.channel.value}' is not available for '{self.method.value}' payments."
            )
        if self.method is PaymentMethod.MOBILE_MONEY:
            if not self.msisdn:
                raise ValueError("A phone number is required for mobile money.")
            self.card = None
        elif self.method in (PaymentMethod.PESAPAL,):
            # PesaPal haitaji card na msisdn - wanashughulikia kwenye checkout yao
            self.msisdn = None
            self.card = None
        else:
            if self.card is None:
                raise ValueError("Card details are required for a bank payment.")
            self.msisdn = None
        return self


class CheckoutResponse(CamelModel):
    payment: PaymentRead
    subscription: SubscriptionRead
    #: Maelezo ya kumwambia mteja afanye nini sasa (mfano kuthibitisha USSD).
    instruction: str
    #: URL ya redirect (PesaPal) — frontend inaredirect hapa.
    redirect_url: str | None = None
