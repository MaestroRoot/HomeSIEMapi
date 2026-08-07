"""MFA — Email OTP for login verification.

Flow:
1. User enables MFA → backend generates OTP, hashes it, stores hash, sends OTP via email
2. Login → Firebase accepts → backend checks mfa_enabled → returns { mfa_required: true, temp_token }
3. User enters OTP → backend verifies hash → returns full session

OTP: 6 digits, random, expires in 5 minutes, max 5 attempts.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

from app.core.config import settings
from app.core.errors import AuthError
from app.core.logging import get_logger

logger = get_logger(__name__)

# In-memory OTP store: temp_token -> { email, hash, expires_at, attempts }
# Production: move to Redis. For a single-server home SIEM this is fine.
_otp_store: dict[str, dict] = {}


def _hash_otp(otp: str, salt: str | None = None) -> str:
    """Hash OTP with SHA-256 + salt for storage."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()
    return f"{salt}:{h}"


def _verify_hash(otp: str, stored: str) -> bool:
    """Verify OTP against stored hash."""
    salt, expected = stored.split(":", 1)
    h = hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()
    return hmac.compare_digest(h, expected)


def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return f"{secrets.randbelow(1000000):06d}"


def create_mfa_challenge(email: str) -> tuple[str, str]:
    """Create an MFA challenge. Returns (temp_token, otp_code).

    The temp_token is sent to the frontend. The otp_code is sent via email.
    """
    # Clean expired entries
    now = time.time()
    expired = [k for k, v in _otp_store.items() if v["expires_at"] < now]
    for k in expired:
        del _otp_store[k]

    # Rate limit: max 3 active challenges per email
    email_challenges = [v for v in _otp_store.values() if v["email"] == email]
    if len(email_challenges) >= 3:
        raise AuthError(
            "Too many verification requests. Wait a few minutes and try again.",
            code="mfa_rate_limited",
        )

    otp = generate_otp()
    temp_token = secrets.token_urlsafe(32)
    ttl = settings.otp_ttl_minutes * 60

    _otp_store[temp_token] = {
        "email": email,
        "hash": _hash_otp(otp),
        "expires_at": now + ttl,
        "attempts": 0,
    }

    logger.info("MFA challenge created for %s (expires in %dm)", email, settings.otp_ttl_minutes)
    return temp_token, otp


def verify_mfa_otp(temp_token: str, otp: str) -> str | None:
    """Verify OTP. Returns the email on success, None on failure.

    Raises AuthError on expired/invalid token.
    """
    record = _otp_store.get(temp_token)
    if record is None:
        raise AuthError(
            "Verification session expired. Log in again.",
            code="mfa_token_invalid",
        )

    if record["expires_at"] < time.time():
        del _otp_store[temp_token]
        raise AuthError(
            "Verification code expired. Log in again.",
            code="mfa_expired",
        )

    if record["attempts"] >= settings.otp_max_attempts:
        del _otp_store[temp_token]
        raise AuthError(
            "Too many wrong attempts. Log in again to get a new code.",
            code="mfa_max_attempts",
        )

    record["attempts"] += 1

    if not _verify_hash(otp, record["hash"]):
        remaining = settings.otp_max_attempts - record["attempts"]
        if remaining <= 0:
            del _otp_store[temp_token]
            raise AuthError(
                "Too many wrong attempts. Log in again to get a new code.",
                code="mfa_max_attempts",
            )
        raise AuthError(
            f"Wrong code. {remaining} attempt(s) remaining.",
            code="mfa_invalid",
        )

    # Success — remove from store
    email = record["email"]
    del _otp_store[temp_token]
    return email
