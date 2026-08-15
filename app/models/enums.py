from enum import Enum


class Role(str, Enum):
    #: Akaunti ya usimamizi wa jukwaa zima (sio ya org). Inaruhusiwa kuona
    #: users na subscriptions za org zote, na kubadilisha plan/role/status.
    ADMIN = "admin"
    OWNER = "owner"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Plan(str, Enum):
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
    TRIALING = "trialing"
    ACTIVE = "active"
    PENDING = "pending"
    PAST_DUE = "past_due"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class PaymentMethod(str, Enum):
    MOBILE_MONEY = "mobile_money"
    BANK_CARD = "bank_card"


class PaymentChannel(str, Enum):
    YAS_MIX = "yas_mix"
    MPESA = "mpesa"
    HALOPESA = "halopesa"
    AIRTEL_MONEY = "airtel_money"
    CARD = "card"


class PaymentStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.OWNER: 2,
    Role.ADMIN: 3,
}

PLAN_RANK: dict[Plan, int] = {
    Plan.FREE: 0,
    Plan.HOME: 1,
    Plan.PRO: 2,
    Plan.BUSINESS: 3,
}

CHANNELS_BY_METHOD: dict[PaymentMethod, tuple[PaymentChannel, ...]] = {
    PaymentMethod.MOBILE_MONEY: (
        PaymentChannel.YAS_MIX,
        PaymentChannel.MPESA,
        PaymentChannel.HALOPESA,
        PaymentChannel.AIRTEL_MONEY,
    ),
    PaymentMethod.BANK_CARD: (PaymentChannel.CARD,),
}
