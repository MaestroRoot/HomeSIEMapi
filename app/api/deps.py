import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthError, ForbiddenError, ServiceUnavailableError
from app.core.firebase import FirebaseIdentity, verify_id_token
from app.core.logging import get_logger
from app.crud import monitoring as monitoring_crud
from app.crud import user as user_crud
from app.db.session import get_db
from app.models.enums import ROLE_RANK, Role
from app.models.user import User

logger = get_logger(__name__)

bearer_scheme = HTTPBearer(auto_error=False, description="Firebase ID token")

DbSession = Annotated[AsyncSession, Depends(get_db)]


async def get_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> FirebaseIdentity:
    """Inathibitisha token pekee, haiguswi na database."""
    if credentials is None or not credentials.credentials:
        raise AuthError("The Authorization header is missing.", code="token_missing")
    return await verify_id_token(credentials.credentials)


CurrentIdentity = Annotated[FirebaseIdentity, Depends(get_identity)]


async def get_current_user(
    request: Request,
    identity: CurrentIdentity,
    db: DbSession,
) -> User:
    """Identity iliyothibitishwa -> row ya `users`.

    Inaunda user mara ya kwanza (auto-provisioning) ili endpoint yoyote ifanye kazi
    hata kama frontend haikuita `/auth/session` kwanza.
    """
    try:
        user, _ = await user_crud.provision_from_firebase(db, identity)
    except SQLAlchemyError as exc:
        logger.error("Database haipatikani wakati wa auth: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    if not user.is_active:
        raise ForbiddenError("This account has been suspended.", code="user_inactive")

    request.state.user = user
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(minimum: Role) -> Callable[[User], User]:
    """Dependency factory: `Depends(require_role(Role.ANALYST))`.

    Inatumia ngazi (viewer < analyst < owner), sio ulinganisho wa moja kwa moja.
    """

    async def _check(user: CurrentUser) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise ForbiddenError(
                f"This action needs the '{minimum.value}' role or higher.",
                code="insufficient_role",
            )
        return user

    return _check


RequireAnalyst = Annotated[User, Depends(require_role(Role.ANALYST))]
RequireOwner = Annotated[User, Depends(require_role(Role.OWNER))]


async def require_admin(user: CurrentUser) -> User:
    """Admin pekee (ulioumbwa kwa `ADMIN_EMAIL`), si owner wa org.

    Hii ni ulinganisho wa moja kwa moja, SIO ngazi: owner hapaswi kupata
    ruhusa ya admin kwa sababu tu ana kiwango cha juu kwenye org yake.
    """
    if user.role is not Role.ADMIN:
        raise ForbiddenError(
            "This action is reserved for the platform administrator.",
            code="admin_only",
        )
    return user


RequireAdmin = Annotated[User, Depends(require_admin)]


async def get_sensor_org(
    db: DbSession,
    x_sensor_token: Annotated[str | None, Header()] = None,
) -> uuid.UUID:
    """Auth ya sensor (box/agent), si Firebase. Inasoma header `X-Sensor-Token`
    na kurudisha organization id. Sensor si mtumiaji, ni kifaa kinachotuma data."""
    if not x_sensor_token:
        raise AuthError("The X-Sensor-Token header is missing.", code="sensor_token_missing")
    try:
        org_id = await monitoring_crud.org_id_for_sensor_token(db, x_sensor_token)
    except SQLAlchemyError as exc:
        logger.error("Database haipatikani wakati wa sensor auth: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc
    if org_id is None:
        raise AuthError("This sensor token is invalid or revoked.", code="sensor_token_invalid")
    return org_id


SensorOrg = Annotated[uuid.UUID, Depends(get_sensor_org)]
