import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.enums import InvitationStatus, Role
from app.models.security import Invitation

INVITE_TTL_DAYS = 7


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def get_pending_for_email(
    db: AsyncSession, organization_id: uuid.UUID, email: str
) -> Invitation | None:
    stmt = select(Invitation).where(
        Invitation.organization_id == organization_id,
        func.lower(Invitation.email) == email.lower(),
        Invitation.status == InvitationStatus.PENDING,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    invited_by_id: uuid.UUID,
    email: str,
    role: Role,
) -> tuple[Invitation, str]:
    """Inarudisha (invitation, raw_token). Token yenyewe haihifadhiwi."""
    token = secrets.token_urlsafe(32)
    invitation = Invitation(
        organization_id=organization_id,
        invited_by_id=invited_by_id,
        email=email.lower(),
        role=role,
        token_hash=_hash(token),
        expires_at=_now() + timedelta(days=INVITE_TTL_DAYS),
    )
    db.add(invitation)
    await db.commit()
    await db.refresh(invitation)
    return invitation, token


async def mark_sent(db: AsyncSession, invitation: Invitation, sent: bool) -> Invitation:
    invitation.email_sent = sent
    await db.commit()
    await db.refresh(invitation)
    return invitation


async def list_for_organization(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[Invitation]:
    stmt = (
        select(Invitation)
        .where(Invitation.organization_id == organization_id)
        .order_by(Invitation.created_at.desc())
        .options(selectinload(Invitation.invited_by))
    )
    return list((await db.execute(stmt)).scalars())


async def get_by_id(db: AsyncSession, invitation_id: uuid.UUID) -> Invitation | None:
    return await db.get(Invitation, invitation_id)


async def revoke(db: AsyncSession, invitation: Invitation) -> Invitation:
    invitation.status = InvitationStatus.REVOKED
    await db.commit()
    await db.refresh(invitation)
    return invitation


async def accept_matching(db: AsyncSession, email: str) -> Invitation | None:
    """Inaitwa wakati wa provisioning: je, mtu huyu alialikwa mahali fulani?

    Ikiwa ndio, inarudisha mwaliko wa kwanza halali ili user aundwe ndani ya
    organization ile badala ya kuundiwa yake mwenyewe.
    """
    stmt = (
        select(Invitation)
        .where(
            func.lower(Invitation.email) == email.lower(),
            Invitation.status == InvitationStatus.PENDING,
            Invitation.expires_at > _now(),
        )
        .order_by(Invitation.created_at.asc())
        .limit(1)
    )
    invitation = (await db.execute(stmt)).scalar_one_or_none()
    if invitation is None:
        return None

    invitation.status = InvitationStatus.ACCEPTED
    invitation.accepted_at = _now()
    return invitation
