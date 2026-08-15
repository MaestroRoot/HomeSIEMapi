"""Admin ya jukwaa zima: users za org zote, subscriptions na takwimu.

Endpoints zote zinahitaji `RequireAdmin` (akaunti ya `ADMIN_EMAIL` pekee),
hivyo hazifikiwi na owner wala analyst wa org yoyote.
"""

import uuid

from fastapi import APIRouter, Query

from app.api.deps import DbSession, RequireAdmin
from app.core.errors import ForbiddenError, NotFoundError
from app.core.firebase import revoke_refresh_tokens
from app.core.logging import get_logger
from app.crud import admin as admin_crud
from app.crud import user as user_crud
from app.models.enums import Plan, Role, SubscriptionStatus
from app.schemas.admin import (
    AdminPlanUpdate,
    AdminRoleUpdate,
    AdminStats,
    AdminStatusUpdate,
    AdminSubscriptionRead,
    AdminUserList,
    AdminUserRead,
)
from app.schemas.common import Message

logger = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def _admin_user_read(user) -> AdminUserRead:
    subscription = user.organization.subscription if user.organization is not None else None
    return AdminUserRead(
        id=user.id,
        name=user.name,
        email=user.email,
        phone=user.phone,
        role=user.role,
        plan=user.plan,
        mfa_enabled=user.mfa_enabled,
        email_verified=user.email_verified,
        is_active=user.is_active,
        avatar_url=user.avatar_url,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        organization_id=user.organization_id,
        organization_name=user.organization.name if user.organization is not None else None,
        subscription=(
            AdminSubscriptionRead(
                plan=subscription.plan,
                status=subscription.status,
                price_tzs=subscription.price_tzs,
                currency=subscription.currency,
                current_period_end=subscription.current_period_end,
                trial_ends_at=subscription.trial_ends_at,
                auto_renew=subscription.auto_renew,
            )
            if subscription is not None
            else None
        ),
    )


@router.get("/stats", response_model=AdminStats, summary="Platform-wide statistics")
async def platform_stats(admin: RequireAdmin, db: DbSession) -> AdminStats:
    data = await admin_crud.platform_stats(db)
    return AdminStats(**data)


@router.get("/users", response_model=AdminUserList, summary="Every user across every org")
async def list_users(
    admin: RequireAdmin,
    db: DbSession,
    q: str | None = Query(default=None, max_length=120, description="Search by name or email"),
    role: Role | None = None,
    plan: Plan | None = None,
    subscription_status: SubscriptionStatus | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AdminUserList:
    rows, total = await admin_crud.list_all_users(
        db,
        query=q,
        role=role,
        plan=plan,
        subscription_status=subscription_status,
        limit=limit,
        offset=offset,
    )
    return AdminUserList(items=[_admin_user_read(row) for row in rows], total=total)


@router.patch("/users/{user_id}/plan", response_model=AdminUserRead, summary="Change an org's plan")
async def update_user_plan(
    user_id: uuid.UUID,
    payload: AdminPlanUpdate,
    admin: RequireAdmin,
    db: DbSession,
) -> AdminUserRead:
    """Inabadilisha kifurushi cha org ya user (subscription + org + users zote)."""
    user = await user_crud.get_by_id(db, user_id)
    if user is None:
        raise NotFoundError("No such user.", code="user_not_found")

    await admin_crud.set_plan(db, user.organization_id, payload.plan)

    # Reload ili subscription mpya ionekane.
    user = await user_crud.get_by_id(db, user_id)
    if user is None:  # pragma: no cover - hatujasema kufuta, tu default yale
        raise NotFoundError("No such user.", code="user_not_found")
    return _admin_user_read(user)


@router.patch("/users/{user_id}/role", response_model=AdminUserRead, summary="Change a user's role")
async def update_user_role(
    user_id: uuid.UUID,
    payload: AdminRoleUpdate,
    admin: RequireAdmin,
    db: DbSession,
) -> AdminUserRead:
    user = await user_crud.get_by_id(db, user_id)
    if user is None:
        raise NotFoundError("No such user.", code="user_not_found")

    # Usijiondoe wewe mwenyewe kwenye ruhusa ya admin.
    if user.id == admin.id and payload.role is not Role.ADMIN:
        raise ForbiddenError(
            "You cannot remove your own administrator role.", code="self_demotion"
        )

    updated = await user_crud.set_role(db, user, payload.role)
    return _admin_user_read(updated)


@router.patch(
    "/users/{user_id}/status",
    response_model=AdminUserRead,
    summary="Suspend or activate a user",
)
async def update_user_status(
    user_id: uuid.UUID,
    payload: AdminStatusUpdate,
    admin: RequireAdmin,
    db: DbSession,
) -> AdminUserRead:
    user = await user_crud.get_by_id(db, user_id)
    if user is None:
        raise NotFoundError("No such user.", code="user_not_found")

    if user.id == admin.id and not payload.is_active:
        raise ForbiddenError("You cannot suspend your own account.", code="self_suspend")

    user.is_active = payload.is_active
    await db.commit()
    await db.refresh(user)

    if not payload.is_active:
        # Best-effort: futa refresh tokens zake ili asibaki kwenye devices.
        revoke_refresh_tokens(user.firebase_uid)
        logger.info("Admin amesimamisha akaunti ya %s", user.email)
    else:
        logger.info("Admin amerejesha akaunti ya %s", user.email)

    return _admin_user_read(user)


@router.post(
    "/users/{user_id}/unlock",
    response_model=Message,
    summary="Resume an org's trial subscription",
)
async def unlock_subscription(
    user_id: uuid.UUID,
    admin: RequireAdmin,
    db: DbSession,
) -> Message:
    """Inarudisha subscription ya org ya user hadi ACTIVE ikiwa ilikuwa expired
    (mfano trial iliyomalizika). Kifurushi hakibadiliki, status ndiyo inabadilika.
    """
    user = await user_crud.get_by_id(db, user_id)
    if user is None:
        raise NotFoundError("No such user.", code="user_not_found")

    subscription = await admin_crud.set_plan(db, user.organization_id, user.organization.plan)
    return Message(
        detail=f"{user.email}'s workspace is now active on the {subscription.plan.value} plan.",
        code="subscription_activated",
    )
