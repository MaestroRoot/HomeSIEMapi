import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.security import PasswordResetCode

logger = get_logger(__name__)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def generate_code() -> str:
    """OTP ya tarakimu 6. `secrets` sio `random`, hii ni credential."""
    return f"{secrets.randbelow(1_000_000):06d}"


async def invalidate_existing(db: AsyncSession, email: str) -> None:
    """Ombi jipya linafuta code zote za zamani, ili kuwe na moja hai kwa wakati."""
    await db.execute(
        update(PasswordResetCode)
        .where(
            PasswordResetCode.email == email.lower(),
            PasswordResetCode.consumed_at.is_(None),
        )
        .values(consumed_at=_now())
    )


async def create(db: AsyncSession, email: str, *, ip: str | None = None) -> str:
    """Inaunda OTP mpya na kurudisha code YENYEWE (haihifadhiwi popote)."""
    email = email.lower()
    await invalidate_existing(db, email)

    code = generate_code()
    record = PasswordResetCode(
        email=email,
        code_hash=_hash(code),
        expires_at=_now() + timedelta(minutes=settings.otp_ttl_minutes),
        requested_ip=ip,
    )
    db.add(record)
    await db.commit()
    return code


async def _active_for(db: AsyncSession, email: str) -> PasswordResetCode | None:
    stmt = (
        select(PasswordResetCode)
        .where(
            PasswordResetCode.email == email.lower(),
            PasswordResetCode.consumed_at.is_(None),
        )
        .order_by(PasswordResetCode.created_at.desc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def verify(db: AsyncSession, email: str, code: str) -> str | None:
    """Inarudisha reset token ikiwa OTP ni sahihi, None ikiwa sio.

    Kila jaribio linahesabiwa. Ikifika `otp_max_attempts`, code inakufa hata
    kama jaribio linalofuata lingekuwa sahihi, ili mtu asiweze kubahatisha
    code 1,000,000 zote.
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

    reset_token = secrets.token_urlsafe(32)
    record.verified_at = _now()
    record.reset_token_hash = _hash(reset_token)
    await db.commit()
    return reset_token


async def consume(db: AsyncSession, email: str, reset_token: str) -> bool:
    """Inathibitisha reset token na kuifunga. Inarudisha False ikiwa si halali."""
    record = await _active_for(db, email)
    if record is None or record.reset_token_hash is None or record.verified_at is None:
        return False

    if record.expires_at <= _now():
        record.consumed_at = _now()
        await db.commit()
        return False

    if not secrets.compare_digest(record.reset_token_hash, _hash(reset_token)):
        return False

    record.consumed_at = _now()
    await db.commit()
    return True
