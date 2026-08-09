import math
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.core.payments import GatewayResult, new_reference
from app.core.plans import CURRENCY, DEFAULT_PLAN, TRIAL_DAYS, TRIAL_PLAN, price_of
from app.models.enums import (
    PaymentChannel,
    PaymentMethod,
    PaymentStatus,
    Plan,
    SubscriptionStatus,
)
from app.models.organization import Organization
from app.models.payment import Payment
from app.models.subscription import Subscription
from app.models.user import User

logger = get_logger(__name__)

#: Muda wa kifurushi kimoja. Bado hakuna mzunguko wa mwaka.
PERIOD_DAYS = 30


async def get_for_organization(
    db: AsyncSession, organization_id: uuid.UUID
) -> Subscription | None:
    stmt = select(Subscription).where(Subscription.organization_id == organization_id)
    return (await db.execute(stmt)).scalar_one_or_none()


async def ensure_subscription(db: AsyncSession, organization_id: uuid.UUID) -> Subscription:
    """Inarudisha subscription ya org, ikishughulikia trial iliyoisha.

    Trial haina cron inayoifuta. Badala yake tunaikagua kila inaposomwa, hivyo
    mtu asiendelee kutumia Business baada ya siku 30 hata kama hakuna job
    iliyokimbia usiku.
    """
    existing = await get_for_organization(db, organization_id)
    if existing is not None:
        return await _expire_trial_if_due(db, existing)

    now = datetime.now(timezone.utc)
    trial_ends = now + timedelta(days=TRIAL_DAYS)
    subscription = Subscription(
        organization_id=organization_id,
        plan=TRIAL_PLAN,
        status=SubscriptionStatus.TRIALING,
        price_tzs=0,
        currency=CURRENCY,
        started_at=now,
        trial_ends_at=trial_ends,
        current_period_end=trial_ends,
        auto_renew=False,
    )
    db.add(subscription)
    await db.commit()
    await db.refresh(subscription)
    return subscription


async def _expire_trial_if_due(db: AsyncSession, subscription: Subscription) -> Subscription:
    if subscription.status is not SubscriptionStatus.TRIALING:
        return subscription
    if subscription.trial_ends_at is None or subscription.trial_ends_at > datetime.now(timezone.utc):
        return subscription

    subscription.plan = DEFAULT_PLAN
    subscription.status = SubscriptionStatus.EXPIRED
    subscription.price_tzs = price_of(DEFAULT_PLAN)
    subscription.current_period_end = None
    await _sync_plan_to_org_and_users(db, subscription.organization_id, DEFAULT_PLAN)
    await db.commit()
    await db.refresh(subscription)

    logger.info("Trial imeisha kwa org=%s, imeshushwa hadi Free", subscription.organization_id)
    return subscription


def days_left(subscription: Subscription) -> int | None:
    """Siku zilizobaki za trial, zikizungushwa juu. None ikiwa hayuko kwenye trial.

    Kuzungusha juu maana yake saa 3 zilizobaki zinaonekana kama 'siku 1', sio
    'siku 0', ambayo ingemwambia mtu ameshaisha wakati bado anaweza kutumia.
    """
    if subscription.status is not SubscriptionStatus.TRIALING or subscription.trial_ends_at is None:
        return None
    seconds = (subscription.trial_ends_at - datetime.now(timezone.utc)).total_seconds()
    return max(0, math.ceil(seconds / 86_400))


async def latest_pending_payment(
    db: AsyncSession, organization_id: uuid.UUID
) -> Payment | None:
    stmt = (
        select(Payment)
        .where(
            Payment.organization_id == organization_id,
            Payment.status.in_([PaymentStatus.PENDING, PaymentStatus.PROCESSING]),
        )
        .order_by(Payment.created_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def list_payments(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int = 20, offset: int = 0
) -> tuple[list[Payment], int]:
    total = await db.scalar(
        select(func.count(Payment.id)).where(Payment.organization_id == organization_id)
    )
    stmt = (
        select(Payment)
        .where(Payment.organization_id == organization_id)
        .order_by(Payment.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = list((await db.execute(stmt)).scalars())
    return rows, int(total or 0)


async def get_payment_by_reference(db: AsyncSession, reference: str) -> Payment | None:
    stmt = (
        select(Payment)
        .where(Payment.reference == reference)
        .options(selectinload(Payment.subscription))
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def get_payment_by_provider_reference(db: AsyncSession, provider_reference: str) -> Payment | None:
    stmt = (
        select(Payment)
        .where(Payment.provider_reference == provider_reference)
        .options(selectinload(Payment.subscription))
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_payment_record(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    subscription_id: uuid.UUID,
    initiated_by_id: uuid.UUID,
    plan: Plan,
    amount_tzs: int,
    method: PaymentMethod,
    channel: PaymentChannel,
    reference: str,
    provider: str = "clickpesa",
) -> Payment:
    payment = Payment(
        organization_id=organization_id,
        subscription_id=subscription_id,
        initiated_by_id=initiated_by_id,
        plan=plan,
        amount_tzs=amount_tzs,
        currency=CURRENCY,
        method=method,
        channel=channel,
        status=PaymentStatus.PROCESSING,
        reference=reference,
        provider=provider,
    )
    db.add(payment)
    await db.flush()
    await db.refresh(payment)
    return payment


async def start_checkout(
    db: AsyncSession,
    *,
    user: User,
    subscription: Subscription,
    plan: Plan,
    method: PaymentMethod,
    channel: PaymentChannel,
    msisdn: str | None,
    card_last4: str | None,
    card_brand: str | None,
    card_number: str | None = None,
    card_holder: str | None = None,
    card_expiry_month: int | None = None,
    card_expiry_year: int | None = None,
    card_cvv: str | None = None,
    charge: "GatewayCall",
) -> tuple[Payment, Subscription, str]:
    """Inarekodi malipo, inapiga gateway, kisha inaweka subscription 'pending'.

    Kifurushi HAKIBADILIKI hapa. Kinabadilika pale tu malipo yatakapothibitishwa
    (`confirm_payment`), ndio maana `subscription.plan` bado ni ya zamani hadi
    hapo. Hii inazuia mtu kupata Business kwa kubonyeza checkout tu.
    """
    amount = price_of(plan)
    payment = Payment(
        organization_id=user.organization_id,
        subscription_id=subscription.id,
        initiated_by_id=user.id,
        plan=plan,
        amount_tzs=amount,
        currency=CURRENCY,
        method=method,
        channel=channel,
        status=PaymentStatus.PENDING,
        msisdn=msisdn,
        card_last4=card_last4,
        card_brand=card_brand,
        reference=new_reference(),
    )
    db.add(payment)
    await db.flush()

    result: GatewayResult = await charge(
        reference=payment.reference,
        amount_tzs=amount,
        method=method,
        channel=channel,
        msisdn=msisdn,
        card_last4=card_last4,
        card_brand=card_brand,
        card_number=card_number,
        card_holder=card_holder,
        card_expiry_month=card_expiry_month,
        card_expiry_year=card_expiry_year,
        card_cvv=card_cvv,
    )

    payment.status = result.status
    payment.provider_reference = result.provider_reference
    payment.failure_reason = result.failure_reason

    if result.status is PaymentStatus.SUCCEEDED:
        _apply_plan(subscription, plan, amount)
        payment.paid_at = datetime.now(timezone.utc)
    elif result.status in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
        subscription.status = SubscriptionStatus.PENDING

    await db.commit()
    await db.refresh(payment)
    await db.refresh(subscription)
    return payment, subscription, result.instruction


async def confirm_payment(db: AsyncSession, payment: Payment) -> Payment:
    """Inaitwa na webhook ya gateway (au admin) malipo yakithibitishwa."""
    if payment.status is PaymentStatus.SUCCEEDED:
        return payment

    payment.status = PaymentStatus.SUCCEEDED
    payment.paid_at = datetime.now(timezone.utc)

    subscription = await get_for_organization(db, payment.organization_id)
    if subscription is not None:
        _apply_plan(subscription, payment.plan, payment.amount_tzs)
        await _sync_plan_to_org_and_users(db, payment.organization_id, payment.plan)

    await db.commit()
    await db.refresh(payment)
    logger.info("Malipo yamethibitishwa: %s -> %s", payment.reference, payment.plan.value)
    return payment


async def fail_payment(db: AsyncSession, payment: Payment, reason: str) -> Payment:
    payment.status = PaymentStatus.FAILED
    payment.failure_reason = reason

    subscription = await get_for_organization(db, payment.organization_id)
    if subscription is not None and subscription.status is SubscriptionStatus.PENDING:
        # Rudi kwenye hali ya awali, kifurushi hakikubadilika.
        subscription.status = SubscriptionStatus.ACTIVE

    await db.commit()
    await db.refresh(payment)
    return payment


def _apply_plan(subscription: Subscription, plan: Plan, amount_tzs: int) -> None:
    now = datetime.now(timezone.utc)
    subscription.plan = plan
    subscription.status = SubscriptionStatus.ACTIVE
    subscription.price_tzs = amount_tzs
    subscription.currency = CURRENCY
    subscription.started_at = subscription.started_at or now
    subscription.current_period_end = now + timedelta(days=PERIOD_DAYS)
    subscription.cancelled_at = None
    # Malipo halisi yamefika, trial haihitajiki tena.
    subscription.trial_ends_at = None
    subscription.auto_renew = True


async def _sync_plan_to_org_and_users(
    db: AsyncSession, organization_id: uuid.UUID, plan: Plan
) -> None:
    """`plan` inarudiwa kwenye `organizations` na `users` ili endpoints
    zinazoisoma zisilazimike ku-join `subscriptions` kila mara."""
    org = await db.get(Organization, organization_id)
    if org is not None:
        org.plan = plan

    members = (
        await db.execute(select(User).where(User.organization_id == organization_id))
    ).scalars()
    for member in members:
        member.plan = plan


class GatewayCall:
    """Typing helper tu, `.charge` ya gateway (async) inatosheleza umbo hili."""

    async def __call__(
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
    ) -> GatewayResult:  # pragma: no cover
        raise NotImplementedError
