from enum import Enum


class Role(str, Enum):
    """Values hizi zinalingana na `Role` ya frontend (AuthContext.tsx)."""

    OWNER = "owner"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Plan(str, Enum):
    """Vifurushi. `Free` ndio anachopewa kila mtu anayejisajili.

    Bei ziko `app/core/plans.py`, sio hapa, kwa sababu bei hubadilika mara nyingi
    kuliko majina ya vifurushi na hatutaki migration kila mara bei inapopanda.
    """

    FREE = "Free"
    HOME = "Home"
    PRO = "Pro"
    BUSINESS = "Business"


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SubscriptionStatus(str, Enum):
    TRIALING = "trialing"    # siku 30 za Business bila malipo
    ACTIVE = "active"
    PENDING = "pending"      # malipo yameanzishwa, bado hayajathibitishwa
    PAST_DUE = "past_due"
    EXPIRED = "expired"      # trial imeisha, hakuna malipo yaliyofuata
    CANCELLED = "cancelled"


class PaymentMethod(str, Enum):
    MOBILE_MONEY = "mobile_money"
    BANK_CARD = "bank_card"
    PESAPAL = "pesapal"
    PAYPAL = "paypal"  # deprecated — kept for old records


class PaymentChannel(str, Enum):
    """Watoa huduma. Za simu ni za Tanzania, card inapita kwa gateway."""

    YAS_MIX = "yas_mix"
    MPESA = "mpesa"
    HALOPESA = "halopesa"
    AIRTEL_MONEY = "airtel_money"
    CARD = "card"
    PESAPAL = "pesapal"
    PAYPAL = "paypal"  # deprecated — kept for old records


class PaymentStatus(str, Enum):
    PENDING = "pending"          # tumeirekodi, bado hatujampeleka kwa gateway
    PROCESSING = "processing"    # gateway inasubiri mteja athibitishe (USSD push)
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: Nani anaweza kufanya nini. Namba kubwa = ruhusa zaidi.
ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.OWNER: 2,
}

#: Kifurushi kipi ni kikubwa kuliko kipi. Kinatumika kuangalia entitlements.
PLAN_RANK: dict[Plan, int] = {
    Plan.FREE: 0,
    Plan.HOME: 1,
    Plan.PRO: 2,
    Plan.BUSINESS: 3,
}

#: Channel zipi zinaruhusiwa kwa kila method.
CHANNELS_BY_METHOD: dict[PaymentMethod, tuple[PaymentChannel, ...]] = {
    PaymentMethod.MOBILE_MONEY: (
        PaymentChannel.YAS_MIX,
        PaymentChannel.MPESA,
        PaymentChannel.HALOPESA,
        PaymentChannel.AIRTEL_MONEY,
    ),
    PaymentMethod.BANK_CARD: (PaymentChannel.CARD, PaymentChannel.PESAPAL),
    PaymentMethod.PESAPAL: (PaymentChannel.PESAPAL,),
}
