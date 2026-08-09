from fastapi import APIRouter, Query
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.config import settings
from app.core.errors import AppError, NotFoundError, ServiceUnavailableError
from app.core.logging import get_logger
from app.core.payments import get_gateway
from app.core.plans import CURRENCY, PLAN_ORDER, price_of, spec_for
from app.crud import subscription as sub_crud
from app.models.enums import PaymentChannel, PaymentMethod, PaymentStatus, Plan
from app.schemas.common import CamelModel
from app.schemas.subscription import (
    CheckoutRequest,
    CheckoutResponse,
    PaymentList,
    PaymentRead,
    PlanCatalogue,
    PlanLimitsRead,
    PlanRead,
    SubscriptionRead,
    SubscriptionState,
    card_brand_of,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])


def _subscription_read(subscription) -> SubscriptionRead:
    """`trialDaysLeft` inahesabiwa wakati wa kusoma, haihifadhiwi."""
    read = SubscriptionRead.model_validate(subscription)
    read.trial_days_left = sub_crud.days_left(subscription)
    return read


def _catalogue() -> PlanCatalogue:
    plans = []
    for plan in PLAN_ORDER:
        spec = spec_for(plan)
        plans.append(
            PlanRead(
                plan=spec.plan,
                label=spec.label,
                tagline=spec.tagline,
                price_tzs=spec.price_tzs,
                currency=CURRENCY,
                limits=PlanLimitsRead(
                    devices=spec.limits.devices,
                    retention_days=spec.limits.retention_days,
                    ai_requests_per_day=spec.limits.ai_requests_per_day,
                    seats=spec.limits.seats,
                ),
                modules=list(spec.modules),
                highlights=list(spec.highlights),
                recommended=spec.recommended,
            )
        )
    return PlanCatalogue(currency=CURRENCY, plans=plans)


@router.get("/plans", response_model=PlanCatalogue, summary="Every plan and its price")
async def list_plans() -> PlanCatalogue:
    """Haihitaji kuwa umeingia, ukurasa wa bei unaweza kuisoma."""
    return _catalogue()


@router.get("/me", response_model=SubscriptionState, summary="The plan this workspace is on")
async def read_my_subscription(user: CurrentUser, db: DbSession) -> SubscriptionState:
    try:
        subscription = await sub_crud.ensure_subscription(db, user.organization_id)
        pending = await sub_crud.latest_pending_payment(db, user.organization_id)
    except SQLAlchemyError as exc:
        logger.error("Kusoma subscription kumeshindwa: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    spec = spec_for(subscription.plan)
    return SubscriptionState(
        subscription=_subscription_read(subscription),
        catalogue=_catalogue(),
        modules=list(spec.modules),
        limits=PlanLimitsRead(
            devices=spec.limits.devices,
            retention_days=spec.limits.retention_days,
            ai_requests_per_day=spec.limits.ai_requests_per_day,
            seats=spec.limits.seats,
        ),
        pending_payment=PaymentRead.model_validate(pending) if pending else None,
    )


@router.post("/checkout", response_model=CheckoutResponse, summary="Start a payment")
async def checkout(
    payload: CheckoutRequest,
    user: RequireOwner,
    db: DbSession,
) -> CheckoutResponse:
    """Owner pekee ndiye anaweza kubadilisha kifurushi cha org.

    Kifurushi hakibadiliki hapa. Kinabadilika pale malipo yatakapothibitishwa.
    """
    if payload.plan is Plan.FREE:
        raise AppError("The Free plan does not need a payment.", code="plan_not_payable")

    try:
        subscription = await sub_crud.ensure_subscription(db, user.organization_id)

        if subscription.plan is payload.plan:
            raise AppError(
                f"You are already on the {spec_for(payload.plan).label} plan.",
                code="plan_unchanged",
            )

        existing = await sub_crud.latest_pending_payment(db, user.organization_id)
        if existing is not None:
            raise AppError(
                "A payment is already waiting to be confirmed. Finish or cancel it first.",
                code="payment_in_progress",
            )

        card = payload.card
        payment, subscription, instruction = await sub_crud.start_checkout(
            db,
            user=user,
            subscription=subscription,
            plan=payload.plan,
            method=payload.method,
            channel=payload.channel,
            msisdn=payload.msisdn,
            # Namba kamili ya card haiendi mbali zaidi ya hapa.
            card_last4=card.number[-4:] if card else None,
            card_brand=card_brand_of(card.number) if card else None,
            card_number=card.number if card else None,
            card_holder=card.holder if card else None,
            card_expiry_month=card.expiry_month if card else None,
            card_expiry_year=card.expiry_year if card else None,
            card_cvv=card.cvv if card else None,
            charge=get_gateway(payload.method).charge,
        )
    except SQLAlchemyError as exc:
        logger.error("Checkout imeshindwa: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    logger.info(
        "Checkout: org=%s plan=%s amount=%s ref=%s",
        user.organization_id,
        payload.plan.value,
        price_of(payload.plan),
        payment.reference,
    )

    return CheckoutResponse(
        payment=PaymentRead.model_validate(payment),
        subscription=_subscription_read(subscription),
        instruction=instruction,
    )


@router.get("/payments", response_model=PaymentList, summary="Payment history")
async def list_my_payments(
    user: CurrentUser,
    db: DbSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PaymentList:
    rows, total = await sub_crud.list_payments(
        db, user.organization_id, limit=limit, offset=offset
    )
    return PaymentList(
        items=[PaymentRead.model_validate(row) for row in rows], total=total
    )


@router.post(
    "/payments/{reference}/cancel",
    response_model=PaymentRead,
    summary="Cancel a pending payment",
)
async def cancel_payment(reference: str, user: RequireOwner, db: DbSession) -> PaymentRead:
    payment = await sub_crud.get_payment_by_reference(db, reference)
    if payment is None or payment.organization_id != user.organization_id:
        raise NotFoundError("That payment does not exist.", code="payment_not_found")

    updated = await sub_crud.fail_payment(db, payment, "Cancelled by the customer.")
    return PaymentRead.model_validate(updated)
