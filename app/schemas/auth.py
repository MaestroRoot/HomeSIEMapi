from pydantic import EmailStr, Field, field_validator

from app.schemas.common import CamelModel
from app.schemas.user import UserRead


class SessionRequest(CamelModel):
    """Frontend inatuma hii mara baada ya Firebase login/signup kufanikiwa.

    Token yenyewe inatoka kwenye header `Authorization: Bearer <idToken>`,
    haiwekwi kwenye body. `name` inatumika tu mara ya kwanza (signup form),
    kwa kuwa Firebase email/password signup haina display name mwanzoni.
    """

    name: str | None = Field(default=None, min_length=2, max_length=120)


class SessionResponse(CamelModel):
    user: UserRead
    is_new_user: bool
    mfa_required: bool = False
    mfa_temp_token: str | None = None


class PasswordResetRequest(CamelModel):
    email: EmailStr


class PasswordResetVerify(CamelModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)

    @field_validator("code")
    @classmethod
    def _digits(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("The code is six digits.")
        return value


class PasswordResetConfirm(CamelModel):
    email: EmailStr
    reset_token: str = Field(min_length=10, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _strength(cls, value: str) -> str:
        if value.isdigit() or value.isalpha():
            raise ValueError("Use a mix of letters and numbers.")
        return value


class PasswordResetTicket(CamelModel):
    """Inarudi baada ya OTP kuthibitishwa."""

    reset_token: str
    expires_in_minutes: int


class MfaVerifyRequest(CamelModel):
    """Sent after MFA is required during login."""

    temp_token: str = Field(min_length=10, max_length=128)
    code: str = Field(min_length=6, max_length=6)

    @field_validator("code")
    @classmethod
    def _digits(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("The code is six digits.")
        return value


class MfaVerifyResponse(CamelModel):
    """Returned after successful MFA verification."""

    user: UserRead
