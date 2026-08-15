"""OTP ya kuunganisha HomeSIEM Agent kwa akaunti ya email.

Mara ya kwanza agent inaomba code (inatumwa kwa email ya akaunti). Code
ikithibitishwa, sensor token mpya inatolewa kwa org ya mtumiaji na kurudishwa
kwa agent — agent kisha hutumia token hiyo kwenye `/agent/enroll` na kuendelea.
Mfumo huu unarudia `password_reset` ili hata mtu mwenye haki ya kusoma
database asipate code wala token halisi.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.crud import monitoring as monitoring_crud
from app.models.security import AgentOtpCode

logger = get_logger(__name__)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def invalidate_existing(db: AsyncSession, email: str) -> None:
    """Ombi jipya linafuta code zote za zamani, ili kuwe na moja hai kwa wakati."""
    await db.execute(
        update(AgentOtpCode)
        .where(
            AgentOtpCode.email == email.lower(),
            AgentOtpCode.consumed_at.is_(None),
        )
        .values(consumed_at=_now())
    )


async def create(db: AsyncSession, email: str, *, ip: str | None = None) -> str:
    """Inaunda OTP mpya na kurudisha code YENYEWE (haihifadhiwi popote)."""
    email = email.lower()
    await invalidate_existing(db, email)

    code = f"{secrets.randbelow(1_000_000):06d}"
    record = AgentOtpCode(
        email=email,
        code_hash=_hash(code),
        expires_at=_now() + timedelta(minutes=settings.otp_ttl_minutes),
        requested_ip=ip,
    )
    db.add(record)
    await db.commit()
    return code


async def _active_for(db: AsyncSession, email: str) -> AgentOtpCode | None:
    stmt = (
        select(AgentOtpCode)
        .where(
            AgentOtpCode.email == email.lower(),
            AgentOtpCode.consumed_at.is_(None),
        )
        .order_by(AgentOtpCode.created_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def verify_and_issue(
    db: AsyncSession, email: str, code: str, *, organization_id: object
) -> str | None:
    """Inathibitisha OTP na kutolea org sensor token mpya.

    Inarudisha token YENYEWE ikiwa code ni sahihi, None ikiwa sio. Kila jaribio
    linahesabiwa; `otp_max_attempts` ikifikiwa code inakufa.
    """
    record = await _active_for(db, email)
    if record is None:
        return None

    if record.expires_at <= _now():
        record.consumed_at = _now()
        await db.commit()
        return None

    if record.attempts >= settings.otp_max_attempts:
        record.consumed_at = _now()
        await db.commit()
        return None

    record.attempts += 1

    if not secrets.compare_digest(record.code_hash, _hash(code)):
        await db.commit()
        return None

    record.consumed_at = _now()
    _, token = await monitoring_crud.create_sensor_token(
        db, organization_id, label=f"agent:{email}"
    )
    await db.commit()
    logger.info("Agent OTP imethibitishwa kwa %s, token mpya imetolewa", email)
    return token
