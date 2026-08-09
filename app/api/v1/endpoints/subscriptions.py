from fastapi import APIRouter, Query
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.config import settings
from app.core.errors import AppError, NotFoundError, ServiceUnavailableError
from app.core.logging import get_logger
from app.core.payments import ClickPesaGateway, PayPalGateway, get_gateway
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


# PayPal endpoints MUST come before the /checkout endpoint to avoid path conflicts.
# "paypal" path segment would be matched by {reference} in /payments/{reference}/cancel.


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
    # Parse 3DS redirect URL from instruction (PayPal card payments).
    redirect_url = None
    if instruction.startswith("3DS authentication required: "):
        redirect_url = instruction[len("3DS authentication required: "):]
        instruction = "3D Secure authentication required to complete payment."

    return CheckoutResponse(
        payment=PaymentRead.model_validate(payment),
        subscription=_subscription_read(subscription),
        instruction=instruction,
        redirect_url=redirect_url,
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


def _status_from_webhook(payload: dict, data: dict) -> PaymentStatus | None:
    """Kadirio la status kutoka body ya webhook (fallback ikiwa verify imeshindwa)."""
    event = str(payload.get("event") or "").upper()
    raw = str(data.get("status") or payload.get("status") or "").upper()
    if event == "PAYMENT RECEIVED" or raw in ("SUCCESS", "SETTLED"):
        return PaymentStatus.SUCCEEDED
    if event == "PAYMENT FAILED" or raw == "FAILED":
        return PaymentStatus.FAILED
    return None


@router.post("/webhook/{secret}", summary="ClickPesa payment webhook (public)")
async def clickpesa_webhook(secret: str, payload: dict, db: DbSession) -> dict:
    """Inaitwa na ClickPesa malipo yanapobadilika hali.

    `secret` kwenye URL ni ulinzi wa kwanza. Kisha HATUAMINI body ya webhook —
    tunauliza ClickPesa status HALISI (`verify_status`) kabla ya kupandisha
    kifurushi, ili mtu asije kutuma webhook ya bandia kupata upgrade bure.
    """
    if not settings.clickpesa_webhook_secret or secret != settings.clickpesa_webhook_secret:
        raise NotFoundError("Not found.", code="not_found")

    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    order_ref = data.get("orderReference") or payload.get("orderReference")
    if not order_ref:
        return {"detail": "ignored", "reason": "no orderReference"}

    payment = await sub_crud.get_payment_by_reference(db, str(order_ref))
    if payment is None:
        logger.warning("Webhook ya ClickPesa: reference haijulikani %s", order_ref)
        return {"detail": "unknown reference"}

    gateway = get_gateway()
    final: PaymentStatus | None = None
    if isinstance(gateway, ClickPesaGateway):
        final = await gateway.verify_status(str(order_ref))
    if final is None:  # verification haikupatikana — tumia body (URL ina siri)
        final = _status_from_webhook(payload, data)

    if final is PaymentStatus.SUCCEEDED:
        await sub_crud.confirm_payment(db, payment)
        return {"detail": "confirmed"}
    if final is PaymentStatus.FAILED:
        await sub_crud.fail_payment(db, payment, str(data.get("message") or "Payment failed."))
        return {"detail": "failed"}
    return {"detail": "acknowledged"}


# --- PayPal ----------------------------------------------------------------

class PayPalOrderRequest(CamelModel):
    plan: Plan
    return_url: str
    cancel_url: str


class PayPalOrderResponse(CamelModel):
    order_id: str
    approve_url: str
    payment_reference: str
    subscription: SubscriptionRead


class PayPalCaptureRequest(CamelModel):
    order_id: str


@router.post("/paypal/create-order", response_model=PayPalOrderResponse, summary="Create PayPal order")
async def create_paypal_order(
    payload: PayPalOrderRequest,
    user: RequireOwner,
    db: DbSession,
) -> PayPalOrderResponse:
    """Anza malipo ya PayPal — ina-create order na kurejesha URL ya approve."""
    if not settings.paypal_ready:
        raise ServiceUnavailableError("PayPal is not configured.", code="paypal_not_configured")

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

        # Create payment record with PROCESSING status
        from app.core.payments import new_reference
        reference = new_reference()
        payment = await sub_crud.create_payment_record(
            db,
            organization_id=user.organization_id,
            subscription_id=subscription.id,
            initiated_by_id=user.id,
            plan=payload.plan,
            amount_tzs=price_of(payload.plan),
            method=PaymentMethod.PAYPAL,
            channel=PaymentChannel.PAYPAL,
            reference=reference,
            provider="paypal",
        )
        subscription.status = PaymentStatus.PENDING
        await db.flush()
    except SQLAlchemyError as exc:
        logger.error("PayPal create order imeshindwa: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    # Create PayPal order
    gateway = get_gateway(PaymentMethod.PAYPAL)
    if not isinstance(gateway, PayPalGateway):
        raise ServiceUnavailableError("PayPal gateway not available.", code="paypal_not_configured")

    try:
        result = await gateway.create_order(
            reference=reference,
            amount_tzs=price_of(payload.plan),
            return_url=payload.return_url,
            cancel_url=payload.cancel_url,
        )
        # Save PayPal order ID as provider_reference
        payment.provider_reference = result["id"]
        await db.flush()
    except Exception as exc:
        logger.error("PayPal API error: %s", exc)
        await sub_crud.fail_payment(db, payment, str(exc)[:200])
        raise ServiceUnavailableError(
            "Could not create PayPal order. Please try again.", code="paypal_api_error"
        ) from exc

    logger.info(
        "PayPal order created: org=%s plan=%s order_id=%s",
        user.organization_id,
        payload.plan.value,
        result["id"],
    )
    return PayPalOrderResponse(
        order_id=result["id"],
        approve_url=result["approve_url"],
        payment_reference=reference,
        subscription=_subscription_read(subscription),
    )


@router.post("/paypal/capture", response_model=CheckoutResponse, summary="Capture PayPal order")
async def capture_paypal_order(
    payload: PayPalCaptureRequest,
    user: RequireOwner,
    db: DbSession,
) -> CheckoutResponse:
    """Capture PayPal order baada ya user ku-approve."""
    if not settings.paypal_ready:
        raise ServiceUnavailableError("PayPal is not configured.", code="paypal_not_configured")

    # Find the payment by provider_reference (PayPal order_id)
    payment = await sub_crud.get_payment_by_provider_reference(db, payload.order_id)
    if payment is None or payment.organization_id != user.organization_id:
        raise NotFoundError("That payment does not exist.", code="payment_not_found")

    if payment.status is PaymentStatus.SUCCEEDED:
        raise AppError("This payment was already captured.", code="payment_already_captured")

    gateway = get_gateway(PaymentMethod.PAYPAL)
    if not isinstance(gateway, PayPalGateway):
        raise ServiceUnavailableError("PayPal gateway not available.", code="paypal_not_configured")

    result = await gateway.capture_order(payload.order_id)

    if result.status is PaymentStatus.SUCCEEDED:
        await sub_crud.confirm_payment(db, payment)
        subscription = await sub_crud.ensure_subscription(db, user.organization_id)
        logger.info("PayPal captured: ref=%s order=%s", payment.reference, payload.order_id)
        return CheckoutResponse(
            payment=PaymentRead.model_validate(payment),
            subscription=_subscription_read(subscription),
            instruction="Payment confirmed! Your plan has been upgraded.",
        )
    else:
        await sub_crud.fail_payment(db, payment, result.failure_reason or "Capture failed")
        raise AppError(
            result.instruction or "PayPal payment could not be captured.",
            code="paypal_capture_failed",
        )


@router.post("/webhook/paypal", summary="PayPal payment webhook (public)")
async def paypal_webhook(payload: dict, db: DbSession) -> dict:
    """Inaitwa na PayPal malipo yanapokamilika."""
    event_type = payload.get("event_type", "")
    resource = payload.get("resource", {})

    if event_type == "PAYMENT.CAPTURE.COMPLETED":
        order_id = resource.get("id") or resource.get("supplementary_data", {}).get("related_ids", {}).get("order_id")
        if not order_id:
            return {"detail": "ignored", "reason": "no order_id"}

        payment = await sub_crud.get_payment_by_provider_reference(db, order_id)
        if payment is None:
            logger.warning("PayPal webhook: unknown order_id %s", order_id)
            return {"detail": "unknown order"}

        if payment.status is not PaymentStatus.SUCCEEDED:
            await sub_crud.confirm_payment(db, payment)
            logger.info("PayPal webhook confirmed: order=%s", order_id)
        return {"detail": "confirmed"}

    return {"detail": "ignored", "event_type": event_type}
