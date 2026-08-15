"""CRUD za admin: users za org zote na takwimu za jukwaa.

Hizi zinapigwa tu kutoka kwenye `app/api/v1/endpoints/admin.py`, ambayo inahitaji
`RequireAdmin` — hivyo ni akaunti ya `ADMIN_EMAIL` pekee inayoweza kufikia.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.crud import subscription as sub_crud
from app.models.enums import Plan, Role, SubscriptionStatus
from app.models.organization import Organization
from app.models.subscription import Subscription
from app.models.user import User

logger = get_logger(__name__)

_SUBSCRIPTION_LOADS = (
    selectinload(User.organization).selectinload(Organization.subscription),
)


async def list_all_users(
    db: AsyncSession,
    *,
    query: str | None = None,
    role: Role | None = None,
    plan: Plan | None = None,
    subscription_status: SubscriptionStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[User], int]:
    """Watu wote kwenye jukwaa, pamoja na org na subscription zao.

    `query` inatafuta email au jina. Vichujio vingine vinalenga org's
    subscription (kwa sababu kifurushi ni cha org, sio cha mtu mmoja mmoja).
    """
    filters = []
    if query:
        needle = f"%{query.strip()}%"
        filters.append(or_(User.email.ilike(needle), User.name.ilike(needle)))
    if role is not None:
        filters.append(User.role == role)
    if plan is not None:
        filters.append(Organization.plan == plan)
    if subscription_status is not None:
        filters.append(Subscription.status == subscription_status)

    count_stmt = select(func.count(User.id)).select_from(User).join(
        Organization, User.organization_id == Organization.id
    ).outerjoin(Subscription, Subscription.organization_id == Organization.id)
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = await db.scalar(count_stmt)

    stmt = (
        select(User)
        .join(Organization, User.organization_id == Organization.id)
        .outerjoin(Subscription, Subscription.organization_id == Organization.id)
        .options(*_SUBSCRIPTION_LOADS)
        .order_by(User.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if filters:
        stmt = stmt.where(*filters)
    rows = list((await db.execute(stmt)).scalars())
    return rows, int(total or 0)


async def platform_stats(db: AsyncSession) -> dict:
    """Takwimu za jukwaa zima kwa ajili ya dashboard ya admin."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=30)

    total_users = int(await db.scalar(select(func.count(User.id))) or 0)
    total_organizations = int(await db.scalar(select(func.count(Organization.id))) or 0)
    active_users_30d = int(
        await db.scalar(
            select(func.count(User.id)).where(User.last_login_at >= since)
        )
        or 0
    )
    new_users_30d = int(
        await db.scalar(select(func.count(User.id)).where(User.created_at >= since))
        or 0
    )
    suspended_users = int(
        await db.scalar(select(func.count(User.id)).where(User.is_active.is_(False)))
        or 0
    )
    admin_users = int(
        await db.scalar(select(func.count(User.id)).where(User.role == Role.ADMIN))
        or 0
    )

    org_rows = (
        await db.execute(
            select(Organization.plan, func.count(Organization.id)).group_by(
                Organization.plan
            )
        )
    ).all()
    subscription_counts = {plan.value: 0 for plan in Plan}
    for plan, count in org_rows:
        subscription_counts[plan.value] = int(count)

    trial_count = int(
        await db.scalar(
            select(func.count(Subscription.id)).where(
                Subscription.status == SubscriptionStatus.TRIALING
            )
        )
        or 0
    )
    paid_subscriptions = int(
        await db.scalar(
            select(func.count(Subscription.id)).where(
                Subscription.plan != Plan.FREE,
                Subscription.status.notin_([SubscriptionStatus.TRIALING]),
            )
        )
        or 0
    )

    return {
        "total_users": total_users,
        "total_organizations": total_organizations,
        "active_users_30d": active_users_30d,
        "new_users_30d": new_users_30d,
        "suspended_users": suspended_users,
        "admin_users": admin_users,
        "subscription_counts": subscription_counts,
        "trial_count": trial_count,
        "paid_subscriptions": paid_subscriptions,
    }


async def set_plan(db: AsyncSession, organization_id: uuid.UUID, plan: Plan) -> Subscription:
    """Inabadilisha kifurushi cha org (subscription + organizations + users).

    Hii ni sawa na kile malipo yaliyofanikiwa yanafanya (`confirm_payment`),
    lakini bila gateway: admin anaweka plan moja kwa moja.
    """
    subscription = await sub_crud.ensure_subscription(db, organization_id)
    now = datetime.now(timezone.utc)
    subscription.plan = plan
    subscription.status = SubscriptionStatus.ACTIVE
    subscription.price_tzs = 0
    subscription.currency = sub_crud.CURRENCY
    subscription.started_at = subscription.started_at or now
    subscription.current_period_end = now + timedelta(days=sub_crud.PERIOD_DAYS)
    subscription.cancelled_at = None
    subscription.trial_ends_at = None
    subscription.auto_renew = False

    await sub_crud._sync_plan_to_org_and_users(db, organization_id, plan)
    await db.commit()
    await db.refresh(subscription)
    logger.info("Admin amebadilisha plan ya org=%s hadi %s", organization_id, plan.value)
    return subscription
