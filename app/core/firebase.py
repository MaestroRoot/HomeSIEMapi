"""Kuthibitisha ID token zinazotoka kwa React client SDK.

Mtiririko:
    React  --(Firebase Client SDK)-->  ID token (JWT)
    React  --Authorization: Bearer <token>-->  FastAPI
    FastAPI --verify_id_token()-->  uid + email + name
    FastAPI --> anatafuta/anaunda user kwenye DB yetu (role/plan ziko kwetu)

Firebase inashughulikia IDENTITY tu. AUTHORIZATION (role, plan, org) ni yetu.

Kuna njia MBILI za kuthibitisha, na app inachagua yenyewe:

1. PUBLIC KEYS (haihitaji siri yoyote, project ID pekee).
   ID token ni JWT iliyosainiwa na Google kwa RS256. Cheti cha umma
   kinapatikana wazi, hivyo tunaweza kuthibitisha saini, `aud`, `iss` na `exp`
   bila kuwa na service account. Hii ndiyo inayotumika kwa default.

2. FIREBASE ADMIN SDK (inahitaji service account JSON).
   Inaongeza uwezo wa kufuta refresh tokens (logout ya papo hapo kwenye
   devices zote) na kuangalia kama akaunti imezimwa. Ikiwa
   `FIREBASE_CREDENTIALS_FILE` ipo, tunatumia hii.

Njia ya 1 inatosha kwa login/signup. Njia ya 2 ni ya ziada.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

import httpx
import jwt
from cryptography.x509 import load_pem_x509_certificate

from app.core.config import settings
from app.core.errors import AuthError, ServiceUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

_init_lock = Lock()
_initialised = False
_admin_available = False

DEV_TOKEN_PREFIX = "dev:"

#: Vyeti vya umma vya Google vinavyosaini ID token zote za Firebase.
_CERT_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)
_ISSUER_PREFIX = "https://securetoken.google.com/"

#: Cache ya vyeti. Google inasema zibadilike kila baada ya masaa kadhaa,
#: tunatumia `max-age` inayotoka kwenye response yenyewe.
_certs: dict[str, str] = {}
_certs_expire_at: float = 0.0


@dataclass(frozen=True)
class FirebaseIdentity:
    """Kile tunachokiamini kutoka kwenye token iliyothibitishwa."""

    uid: str
    email: str
    name: str | None = None
    picture: str | None = None
    email_verified: bool = False
    sign_in_provider: str | None = None
    is_dev: bool = False


def init_firebase() -> None:
    """Huitwa mara moja wakati app inaanza. Haiangushi app ikikosa credentials."""
    global _initialised, _admin_available

    with _init_lock:
        if _initialised:
            return
        _initialised = True

        if not settings.firebase_project_id:
            logger.warning(
                "FIREBASE_PROJECT_ID haipo kwenye .env. Token halisi za Firebase "
                "zitakataliwa kwa sababu hatuwezi kuthibitisha `aud` wala `iss`."
            )

        cred_path = settings.firebase_credentials_file
        adc = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

        if not cred_path and not adc:
            logger.info(
                "Hakuna service account. Tunathibitisha token kwa public keys za Google. "
                "Logout ya papo hapo (revocation) haitapatikana."
            )
            return

        try:
            import firebase_admin
            from firebase_admin import credentials

            if cred_path:
                path = Path(cred_path)
                if not path.is_absolute():
                    path = (Path(__file__).resolve().parents[2] / path).resolve()
                if not path.exists():
                    logger.info(
                        "Faili ya Firebase credentials haipo (%s). Tunaendelea na public keys.",
                        path,
                    )
                    return
                cred = credentials.Certificate(str(path))
                project_id = settings.firebase_project_id or json.loads(
                    path.read_text(encoding="utf-8")
                ).get("project_id")
            else:
                cred = credentials.ApplicationDefault()
                project_id = settings.firebase_project_id

            options = {"projectId": project_id} if project_id else None
            firebase_admin.initialize_app(cred, options)

            _admin_available = True
            logger.info("Firebase Admin imeanzishwa (project=%s)", project_id or "auto")
        except Exception:  # noqa: BLE001, tunataka app iendelee kuwaka
            logger.exception("Firebase Admin imeshindwa kuanza, tunarudi kwenye public keys")


def firebase_available() -> bool:
    """Je, tunaweza kuthibitisha token halisi? Project ID pekee inatosha."""
    return bool(settings.firebase_project_id) or _admin_available


def admin_available() -> bool:
    """Je, tuna service account? Inahitajika kwa revocation pekee."""
    return _admin_available


async def verify_id_token(token: str) -> FirebaseIdentity:
    """Inathibitisha ID token na kurudisha identity. Inarusha `AuthError` ikishindwa."""
    token = (token or "").strip()
    if not token:
        raise AuthError("No token was supplied.", code="token_missing")

    if token.startswith(DEV_TOKEN_PREFIX):
        return _dev_identity(token)

    if _admin_available:
        return _verify_with_admin_sdk(token)

    return await _verify_with_public_keys(token)


# --- Njia 1: public keys ---------------------------------------------------


async def _fetch_certs() -> dict[str, str]:
    """Inapakua vyeti vya Google, ikivihifadhi hadi `max-age` iishe."""
    global _certs, _certs_expire_at

    if _certs and time.monotonic() < _certs_expire_at:
        return _certs

    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.get(_CERT_URL)
            response.raise_for_status()
            certs = response.json()
    except Exception as exc:  # noqa: BLE001, mtandao unaweza kukatika
        if _certs:
            # Tumia vya zamani badala ya kumzuia kila mtu kuingia.
            logger.warning("Kupakua vyeti vya Google kumeshindwa, tunatumia vya zamani: %s", exc)
            return _certs
        logger.error("Kupakua vyeti vya Google kumeshindwa: %s", exc)
        raise ServiceUnavailableError(
            "We cannot reach Google to verify your session right now.",
            code="firebase_certs_unavailable",
        ) from exc

    max_age = 3600
    cache_control = response.headers.get("cache-control", "")
    for part in cache_control.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.removeprefix("max-age="))
            except ValueError:
                pass

    _certs = certs
    _certs_expire_at = time.monotonic() + max(max_age - 60, 60)
    return _certs


async def _verify_with_public_keys(token: str) -> FirebaseIdentity:
    project_id = settings.firebase_project_id
    if not project_id:
        raise ServiceUnavailableError(
            "FIREBASE_PROJECT_ID is not set on this server.",
            code="firebase_not_configured",
        )

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError("That token is not valid.", code="token_invalid") from exc

    kid = header.get("kid")
    if header.get("alg") != "RS256" or not kid:
        raise AuthError("That token is not valid.", code="token_invalid")

    certs = await _fetch_certs()
    pem = certs.get(kid)
    if pem is None:
        # Google amezungusha keys tangu tulipopakua mara ya mwisho.
        _certs_expire_at = 0.0
        certs = await _fetch_certs()
        pem = certs.get(kid)
    if pem is None:
        raise AuthError("That token was signed with an unknown key.", code="token_invalid")

    public_key = load_pem_x509_certificate(pem.encode()).public_key()

    try:
        claims = jwt.decode(
            token,
            public_key,  # type: ignore[arg-type]
            algorithms=["RS256"],
            audience=project_id,
            issuer=f"{_ISSUER_PREFIX}{project_id}",
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Your session has expired. Refresh and try again.", code="token_expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthError(
            "That token belongs to a different Firebase project.", code="token_wrong_project"
        ) from exc
    except jwt.PyJWTError as exc:
        logger.debug("Kuthibitisha token kumeshindwa: %s", exc)
        raise AuthError("That token is not valid.", code="token_invalid") from exc

    uid = claims.get("sub")
    if not uid or not isinstance(uid, str):
        raise AuthError("That token has no subject claim.", code="token_invalid")

    return _identity_from_claims(claims, uid)


# --- Njia 2: Admin SDK -----------------------------------------------------


def _verify_with_admin_sdk(token: str) -> FirebaseIdentity:
    from firebase_admin import auth as fb_auth

    try:
        # check_revoked=False: kuangalia revocation kunapiga Firebase kila request
        # (latency + quota). Token huisha baada ya saa 1 hivyo tunategemea hiyo.
        # Ukihitaji logout ya papo hapo kwenye devices zote, badilisha kuwa True.
        claims = fb_auth.verify_id_token(token, check_revoked=False)
    except fb_auth.ExpiredIdTokenError as exc:
        raise AuthError("Your session has expired. Refresh and try again.", code="token_expired") from exc
    except fb_auth.RevokedIdTokenError as exc:
        raise AuthError("That session was revoked. Sign in again.", code="token_revoked") from exc
    except fb_auth.UserDisabledError as exc:
        raise AuthError("This account has been disabled.", code="user_disabled") from exc
    except Exception as exc:  # noqa: BLE001, token yoyote mbovu
        logger.debug("Kuthibitisha token kumeshindwa: %s", exc)
        raise AuthError("That token is not valid.", code="token_invalid") from exc

    return _identity_from_claims(claims, claims["uid"])


# --- Pamoja ----------------------------------------------------------------


def _identity_from_claims(claims: dict, uid: str) -> FirebaseIdentity:
    email = claims.get("email")
    if not email:
        raise AuthError(
            "This account has no email address. Sign in with a provider that supplies one.", code="email_missing"
        )

    return FirebaseIdentity(
        uid=uid,
        email=str(email).lower(),
        name=claims.get("name"),
        picture=claims.get("picture"),
        email_verified=bool(claims.get("email_verified")),
        sign_in_provider=(claims.get("firebase") or {}).get("sign_in_provider"),
    )


def user_exists(email: str) -> bool | None:
    """True/False ikiwa tunaweza kuangalia, None ikiwa hatuna Admin SDK."""
    if not _admin_available:
        return None

    from firebase_admin import auth as fb_auth

    try:
        fb_auth.get_user_by_email(email)
        return True
    except fb_auth.UserNotFoundError:
        return False
    except Exception:  # noqa: BLE001
        logger.exception("Kuangalia user %s kumeshindwa", email)
        return None


def revoke_refresh_tokens(firebase_uid: str) -> None:
    """Inafuta refresh tokens zote za mtumiaji (logout ya papo hapo).

    Best-effort: haipigi kelele kama service account haipo wala kama Firebase
    inakataa, si jambo la kuangusha request kwa ajili yake.
    """
    if not _admin_available:
        return

    from firebase_admin import auth as fb_auth

    try:
        fb_auth.revoke_refresh_tokens(firebase_uid)
    except Exception:  # noqa: BLE001, revocation isishindwe request
        logger.exception("Kufuta refresh tokens kumeshindwa kwa %s", firebase_uid)


def set_password(email: str, new_password: str) -> None:
    """Inabadilisha nenosiri la Firebase.

    INAHITAJI service account. Firebase haitoi njia yoyote ya kubadilisha
    nenosiri kwa upande wa server bila hiyo, kwa hivyo password reset ya OTP
    haiwezi kukamilika hadi `FIREBASE_CREDENTIALS_FILE` iwekwe.
    """
    if not _admin_available:
        raise ServiceUnavailableError(
            "Password reset needs the Firebase service account key on the server. "
            "Ask an administrator to configure FIREBASE_CREDENTIALS_FILE.",
            code="firebase_admin_required",
        )

    from firebase_admin import auth as fb_auth

    try:
        user = fb_auth.get_user_by_email(email)
        fb_auth.update_user(user.uid, password=new_password)
        # Sessions zote za zamani zinakufa, ndio maana ya kubadilisha nenosiri.
        fb_auth.revoke_refresh_tokens(user.uid)
    except fb_auth.UserNotFoundError as exc:
        raise AuthError("No account matches that email address.", code="user_not_found") from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Kubadilisha nenosiri kumeshindwa kwa %s", email)
        raise ServiceUnavailableError(
            "We could not update the password right now. Try again shortly.",
            code="password_update_failed",
        ) from exc


def _dev_identity(token: str) -> FirebaseIdentity:
    """Token bandia ya development: `dev:mtu@example.com` au `dev:mtu@example.com:Jina Lake`."""
    if not settings.dev_bypass_enabled:
        raise AuthError("Development tokens are not accepted here.", code="dev_bypass_disabled")

    parts = token[len(DEV_TOKEN_PREFIX) :].split(":", 1)
    email = parts[0].strip().lower()
    if "@" not in email:
        raise AuthError("A development token needs an email, for example dev:someone@example.com", code="token_invalid")

    name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
    uid = "dev_" + hashlib.sha256(email.encode()).hexdigest()[:20]

    logger.warning("DEV BYPASS imetumika kwa %s, usiwahi kuiwasha production", email)
    return FirebaseIdentity(
        uid=uid,
        email=email,
        name=name,
        email_verified=True,
        sign_in_provider="dev",
        is_dev=True,
    )
