import uuid

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DbSession, RequireAnalyst, RequireOwner
from app.core.errors import ForbiddenError, NotFoundError
from app.crud import user as user_crud
from app.models.enums import Role
from app.models.user import User
from app.schemas.user import UserList, UserRead, UserRoleUpdate, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserRead)
async def read_own_profile(user: CurrentUser) -> UserRead:
    return UserRead.model_validate(user)


@router.patch("/me", response_model=UserRead)
async def update_own_profile(
    payload: UserUpdate,
    user: CurrentUser,
    db: DbSession,
) -> UserRead:
    """Mtumiaji anaweza kubadilisha jina, avatar na MFA flag yake mwenyewe.

    `role` na `plan` HAZIBADILIKI hapa, hizo ni maamuzi ya server (angalia
    endpoint ya role hapa chini na billing ya baadaye kwa plan).
    """
    updated = await user_crud.update_profile(
        db,
        user,
        name=payload.name,
        avatar_url=payload.avatar_url,
        mfa_enabled=payload.mfa_enabled,
    )
    return UserRead.model_validate(updated)


@router.get("", response_model=UserList)
async def list_organization_users(
    user: RequireAnalyst,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> UserList:
    """Watu walio kwenye organization ya mtumiaji wa sasa. Analyst au zaidi."""
    rows, total = await user_crud.list_by_organization(
        db, user.organization_id, limit=limit, offset=offset
    )
    return UserList(items=[UserRead.model_validate(row) for row in rows], total=total)


@router.patch("/{user_id}/role", response_model=UserRead)
async def update_user_role(
    user_id: uuid.UUID,
    payload: UserRoleUpdate,
    actor: RequireOwner,
    db: DbSession,
) -> UserRead:
    """Owner pekee. Haiwezi kuiacha organization bila owner hata mmoja."""
    target = await user_crud.get_by_id(db, user_id)
    if target is None or target.organization_id != actor.organization_id:
        raise NotFoundError("No such member in this workspace.")

    if target.id == actor.id and payload.role is not Role.OWNER:
        owners = await db.scalar(
            select(func.count(User.id)).where(
                User.organization_id == actor.organization_id,
                User.role == Role.OWNER,
            )
        )
        if int(owners or 0) <= 1:
            raise ForbiddenError(
                "You are the only owner. Promote someone else before stepping down.",
                code="last_owner",
            )

    updated = await user_crud.set_role(db, target, payload.role)
    return UserRead.model_validate(updated)
