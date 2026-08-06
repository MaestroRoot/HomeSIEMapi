from fastapi import APIRouter, BackgroundTasks, Request, status
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentIdentity, CurrentUser, DbSession
from app.core.email import send_password_reset_otp, send_welcome_email
from app.core.errors import AuthError, ServiceUnavailableError
from app.core.firebase import admin_available, set_password
from app.core.logging import get_logger
from app.core.ratelimit import client_key, otp_limiter, session_limiter
from app.crud import password_reset as reset_crud
from app.crud import user as user_crud
from app.schemas.auth import (
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetTicket,
    PasswordResetVerify,
    SessionRequest,
    SessionResponse,
)
from app.schemas.common import Message
from app.schemas.user import UserRead

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/session", response_model=SessionResponse, status_code=status.HTTP_200_OK)
async def create_session(
    request: Request,
    payload: SessionRequest,
    identity: CurrentIdentity,
    db: DbSession,
    background: BackgroundTasks,
) -> SessionResponse:
    """Inaitwa na frontend mara baada ya Firebase login au signup kufanikiwa.

    Header: `Authorization: Bearer <firebaseIdToken>`

    Inaunda user kwenye DB yetu ikiwa hayupo, kisha inarudisha profile kamili
    (role, plan, org), vitu ambavyo Firebase haviijui.
    """
    session_limiter.hit(client_key(request.client.host if request.client else None))

    try:
        user, is_new = await user_crud.provision_from_firebase(db, identity, name=payload.name)
    except SQLAlchemyError as exc:
        logger.error("Kuunda session kumeshindwa: %s", exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    if is_new and not identity.is_dev:
        # Nyuma ya response: signup isisubiri Brevo, wala isishindwe ikikataa.
        background.add_task(send_welcome_email, to_email=user.email, name=user.name)

    return SessionResponse(user=UserRead.model_validate(user), is_new_user=is_new)


@router.get("/me", response_model=UserRead)
async def read_me(user: CurrentUser) -> UserRead:
    """Inarudisha mtumiaji wa sasa. Frontend inaiita wakati wa kuanza (bootstrap)."""
    return UserRead.model_validate(user)


@router.post("/logout", response_model=Message)
async def logout(user: CurrentUser) -> Message:
    """Inafuta refresh tokens zote za mtumiaji upande wa Firebase.

    Hii inafanyika tu ikiwa service account ipo. Bila yake, client inajitoa
    yenyewe (`signOut`) na token iliyopo mkononi inaisha yenyewe baada ya saa
    moja. Kwa SIEM inayohitaji kufukuza mtu papo hapo kwenye devices zote,
    weka service account kisha ubadilishe `check_revoked=True`.
    """
    if admin_available() and not user.firebase_uid.startswith("dev_"):
        from firebase_admin import auth as fb_auth

        try:
            fb_auth.revoke_refresh_tokens(user.firebase_uid)
        except Exception:  # noqa: BLE001, logout isishindwe kwa sababu ya Firebase
            logger.exception("Kufuta refresh tokens kumeshindwa kwa %s", user.email)

    return Message(detail="You have been signed out.", code="logged_out")


# --- Password reset kwa OTP ya Brevo ---------------------------------------


@router.post("/password-reset/request", response_model=Message)
async def request_password_reset(
    request: Request,
    payload: PasswordResetRequest,
    db: DbSession,
    background: BackgroundTasks,
) -> Message:
    """Inatuma OTP ya tarakimu 6 kwenye email.

    Jibu ni lile lile iwe akaunti ipo au haipo. Kama tungejibu tofauti,
    ukurasa huu ungekuwa njia ya kujua email zipi zina akaunti hapa.
    """
    ip = client_key(request.client.host if request.client else None)
    otp_limiter.hit(ip)

    email = payload.email.lower()
    code = await reset_crud.create(db, email, ip=ip)

    background.add_task(send_password_reset_otp, to_email=email, name=None, code=code)

    return Message(
        detail="If that email has an account, a six digit code is on its way.",
        code="otp_sent",
    )


@router.post("/password-reset/verify", response_model=PasswordResetTicket)
async def verify_password_reset(
    request: Request,
    payload: PasswordResetVerify,
    db: DbSession,
) -> PasswordResetTicket:
    """Inabadilisha OTP kuwa reset token ya muda mfupi."""
    otp_limiter.hit(client_key(request.client.host if request.client else None))

    token = await reset_crud.verify(db, payload.email, payload.code)
    if token is None:
        raise AuthError(
            "That code is wrong or has expired. Request a new one.", code="otp_invalid"
        )

    from app.core.config import settings

    return PasswordResetTicket(reset_token=token, expires_in_minutes=settings.otp_ttl_minutes)


@router.post("/password-reset/confirm", response_model=Message)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: DbSession,
) -> Message:
    """Inaweka nenosiri jipya kwa Firebase kisha inafunga OTP.

    ONYO: hii INAHITAJI service account. Firebase haitoi njia yoyote ya
    kubadilisha nenosiri upande wa server bila hiyo.
    """
    ok = await reset_crud.consume(db, payload.email, payload.reset_token)
    if not ok:
        raise AuthError(
            "This reset session is no longer valid. Start again.", code="reset_token_invalid"
        )

    set_password(payload.email, payload.new_password)

    return Message(detail="Your password has been changed. Sign in with it now.", code="password_changed")
