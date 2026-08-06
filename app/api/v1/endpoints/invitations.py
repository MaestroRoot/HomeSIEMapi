import uuid

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, DbSession, RequireOwner
from app.core.config import settings
from app.core.email import send_invitation_email
from app.core.errors import AppError, NotFoundError
from app.core.logging import get_logger
from app.core.plans import spec_for
from app.core.ratelimit import client_key, invite_limiter
from app.crud import invitation as invitation_crud
from app.crud import user as user_crud
from app.models.enums import InvitationStatus
from app.schemas.common import Message
from app.schemas.invitation import InvitationCreate, InvitationList, InvitationRead

logger = get_logger(__name__)

router = APIRouter(prefix="/invitations", tags=["invitations"])


def _to_read(invitation) -> InvitationRead:
    return InvitationRead(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        status=invitation.status,
        email_sent=invitation.email_sent,
        expires_at=invitation.expires_at,
        accepted_at=invitation.accepted_at,
        created_at=invitation.created_at,
        invited_by_name=invitation.invited_by.name if invitation.invited_by else None,
    )


@router.get("", response_model=InvitationList, summary="Invitations for this workspace")
async def list_invitations(user: CurrentUser, db: DbSession) -> InvitationList:
    rows = await invitation_crud.list_for_organization(db, user.organization_id)
    return InvitationList(items=[_to_read(row) for row in rows], total=len(rows))


@router.post("", response_model=InvitationRead, summary="Invite someone by email")
async def invite_member(
    request: Request,
    payload: InvitationCreate,
    user: RequireOwner,
    db: DbSession,
) -> InvitationRead:
    """Owner only. Sends the invitation through Brevo.

    Seat limits come from the plan, so a Free workspace cannot quietly grow
    into a team of ten.
    """
    invite_limiter.hit(client_key(request.client.host if request.client else None))

    email = payload.email.lower()

    if email == user.email.lower():
        raise AppError("You are already in this workspace.", code="self_invite")

    existing_member = await user_crud.get_by_email(db, email)
    if existing_member is not None and existing_member.organization_id == user.organization_id:
        raise AppError("That person is already a member here.", code="already_member")

    if await invitation_crud.get_pending_for_email(db, user.organization_id, email) is not None:
        raise AppError("An invitation is already pending for that address.", code="already_invited")

    members, total_members = await user_crud.list_by_organization(
        db, user.organization_id, limit=1, offset=0
    )
    del members
    pending = [
        row
        for row in await invitation_crud.list_for_organization(db, user.organization_id)
        if row.status is InvitationStatus.PENDING
    ]
    seats = spec_for(user.plan).limits.seats
    if seats and total_members + len(pending) >= seats:
        raise AppError(
            f"Your {user.plan.value} plan covers {seats} seat(s). Upgrade to invite more people.",
            code="seat_limit_reached",
        )

    invitation, token = await invitation_crud.create(
        db,
        organization_id=user.organization_id,
        invited_by_id=user.id,
        email=email,
        role=payload.role,
    )

    accept_url = f"{settings.app_public_url.rstrip('/')}/signup?invite={token}&email={email}"
    sent = await send_invitation_email(
        to_email=email,
        inviter_name=user.name,
        organization=user.organization.name,
        role=payload.role.value,
        accept_url=accept_url,
    )
    invitation = await invitation_crud.mark_sent(db, invitation, sent)

    if not sent:
        logger.warning("Mwaliko wa %s umeundwa lakini email haijatumwa.", email)

    return _to_read(invitation)


@router.post("/{invitation_id}/revoke", response_model=Message, summary="Cancel an invitation")
async def revoke_invitation(
    invitation_id: uuid.UUID, user: RequireOwner, db: DbSession
) -> Message:
    invitation = await invitation_crud.get_by_id(db, invitation_id)
    if invitation is None or invitation.organization_id != user.organization_id:
        raise NotFoundError("That invitation does not exist.", code="invitation_not_found")

    if invitation.status is not InvitationStatus.PENDING:
        raise AppError("Only a pending invitation can be cancelled.", code="not_pending")

    await invitation_crud.revoke(db, invitation)
    return Message(detail="The invitation has been cancelled.", code="invitation_revoked")
