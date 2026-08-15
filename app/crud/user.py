import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.firebase import FirebaseIdentity
from app.core.logging import get_logger
from app.core.plans import CURRENCY, DEFAULT_PLAN, TRIAL_DAYS, TRIAL_PLAN
from app.crud import invitation as invitation_crud
from app.models.enums import Role, SubscriptionStatus
from app.models.organization import Organization
from app.models.subscription import Subscription
from app.models.user import User

logger = get_logger(__name__)

_SLUG_CLEAN = re.compile(r"[^a-z0-9]+")


def _slugify(value: str) -> str:
    slug = _SLUG_CLEAN.sub("-", value.lower()).strip("-")
    return (slug or "org")[:80]


def _display_name(identity: FirebaseIdentity, fallback: str | None = None) -> str:
    """Jina la kuanzia: kutoka form ya signup, kisha Firebase, kisha sehemu ya email."""
    for candidate in (fallback, identity.name):
        if candidate and candidate.strip():
            return candidate.strip()[:120]
    local = identity.email.split("@")[0]
    return re.sub(r"[._-]+", " ", local).title()[:120] or identity.email[:120]


async def get_by_firebase_uid(db: AsyncSession, firebase_uid: str) -> User | None:
    stmt = (
        select(User)
        .where(User.firebase_uid == firebase_uid)
        .options(selectinload(User.organization))
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def get_by_email(db: AsyncSession, email: str) -> User | None:
    stmt = (
        select(User)
        .where(func.lower(User.email) == email.lower())
        .options(selectinload(User.organization))
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def get_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    stmt = select(User).where(User.id == user_id).options(selectinload(User.organization))
    return (await db.execute(stmt)).scalar_one_or_none()


async def provision_from_firebase(
    db: AsyncSession,
    identity: FirebaseIdentity,
    *,
    name: str | None = None,
) -> tuple[User, bool]:
    """Inarudisha (user, is_new). Idempotent, salama kuiita kwenye kila request.

    Mtu wa kwanza kujisajili anaundiwa organization yake mwenyewe na kuwa `owner`.
    Kuongeza watu kwenye org iliyopo (invites) ni kazi ya baadaye.
    """
    user = await get_by_firebase_uid(db, identity.uid)

    if user is None:
        # Akaunti ilishawahi kuundwa kwa email hii lakini kwa provider tofauti.
        existing = await get_by_email(db, identity.email)
        if existing is not None:
            existing.firebase_uid = identity.uid
            user = existing

    if user is not None:
        user.email = identity.email
        user.email_verified = identity.email_verified
        if identity.picture and not user.avatar_url:
            user.avatar_url = identity.picture
        # Akaunti ya admin inaweza kuundwa upya kwenye Firebase bila role kubadilika
        # kwenye DB, hivyo tunaiweka tena kila anapoingia.
        if identity.email == settings.admin_email_lower:
            user.role = Role.ADMIN
        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(user)
        return user, False

    display = _display_name(identity, name)
    now = datetime.now(timezone.utc)

    # Alialikwa na mtu? Ajiunge na org yake badala ya kuundiwa yake mwenyewe.
    invitation = await invitation_crud.accept_matching(db, identity.email)
    if invitation is not None:
        user = User(
            firebase_uid=identity.uid,
            email=identity.email,
            name=display,
            avatar_url=identity.picture,
            role=invitation.role,
            plan=DEFAULT_PLAN,
            email_verified=identity.email_verified,
            last_login_at=now,
            organization_id=invitation.organization_id,
        )
        db.add(user)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            existing = await get_by_firebase_uid(db, identity.uid)
            if existing is None:
                raise
            return existing, False

        await db.refresh(user, attribute_names=["organization"])
        # Kifurushi ni cha org, sio cha mtu mmoja mmoja.
        user.plan = user.organization.plan
        await db.commit()
        logger.info("User mpya amejiunga kwa mwaliko: %s", user.email)
        return user, True

    # Kila mtu mpya anapata Business bure kwa siku 30. Trial ikiisha bila
    # malipo, `ensure_subscription` inamshusha hadi Free.
    trial_ends = now + timedelta(days=TRIAL_DAYS)
    org = Organization(
        name=f"{display}'s workspace",
        slug=f"{_slugify(display)}-{uuid.uuid4().hex[:6]}",
        plan=TRIAL_PLAN,
    )
    org.subscription = Subscription(
        plan=TRIAL_PLAN,
        status=SubscriptionStatus.TRIALING,
        price_tzs=0,
        currency=CURRENCY,
        started_at=now,
        trial_ends_at=trial_ends,
        current_period_end=trial_ends,
        auto_renew=False,
    )
    user = User(
        firebase_uid=identity.uid,
        email=identity.email,
        name=display,
        avatar_url=identity.picture,
        # Admin akaunti inaorg yake kama user mwingine yeyote, lakini role yake
        # inampatia ruhusa ya jukwaa zima (angalia app/api/v1/endpoints/admin.py).
        role=Role.ADMIN if identity.email == settings.admin_email_lower else Role.OWNER,
        plan=TRIAL_PLAN,
        email_verified=identity.email_verified,
        last_login_at=now,
        organization=org,
    )
    db.add(org)
    db.add(user)

    try:
        await db.commit()
    except IntegrityError:
        # Requests mbili za kwanza zimefika kwa wakati mmoja, mmoja ameshinda.
        await db.rollback()
        existing = await get_by_firebase_uid(db, identity.uid)
        if existing is None:
            raise
        logger.info("Provisioning race kwa %s, tumetumia record iliyopo", identity.email)
        return existing, False

    await db.refresh(user, attribute_names=["organization"])
    logger.info("User mpya ameundwa: %s (org=%s)", user.email, org.slug)
    return user, True


async def update_profile(
    db: AsyncSession,
    user: User,
    *,
    name: str | None = None,
    phone: str | None = None,
    avatar_url: str | None = None,
    mfa_enabled: bool | None = None,
    mfa_secret: str | None = None,
) -> User:
    if name is not None:
        user.name = name.strip()
    if phone is not None:
        user.phone = phone.strip() or None
    if avatar_url is not None:
        user.avatar_url = avatar_url or None
    if mfa_enabled is not None:
        user.mfa_enabled = mfa_enabled
    if mfa_secret is not None:
        user.mfa_secret = mfa_secret

    await db.commit()
    await db.refresh(user)
    return user


async def set_role(db: AsyncSession, user: User, role: Role) -> User:
    user.role = role
    await db.commit()
    await db.refresh(user)
    return user


async def list_by_organization(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int = 50, offset: int = 0
) -> tuple[list[User], int]:
    total = await db.scalar(
        select(func.count(User.id)).where(User.organization_id == organization_id)
    )
    stmt = (
        select(User)
        .where(User.organization_id == organization_id)
        .order_by(User.created_at.asc())
        .limit(limit)
        .offset(offset)
        .options(selectinload(User.organization))
    )
    rows = list((await db.execute(stmt)).scalars())
    return rows, int(total or 0)
