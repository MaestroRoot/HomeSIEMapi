import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import InvitationStatus, Role

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class PasswordResetCode(UUIDMixin, TimestampMixin, Base):
    """OTP ya kubadilisha nenosiri, inatumwa kwa Brevo.

    Code YENYEWE haihifadhiwi. Tunahifadhi SHA-256 yake pekee, ili mtu mwenye
    uwezo wa kusoma database asiweze kuchukua akaunti za watu. Ni utaratibu
    ule ule wa password, na hapa unagharimu kitu kidogo sana.
    """

    __tablename__ = "password_reset_codes"

    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Imethibitishwa lakini nenosiri bado halijabadilishwa.
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Imekwisha tumika, haiwezi kutumika tena.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Token ya muda inayotolewa baada ya OTP kuthibitishwa, ndiyo inayoruhusu
    #: kuweka nenosiri jipya bila kurudia OTP.
    reset_token_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)

    requested_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PasswordResetCode {self.email}>"


class Invitation(UUIDMixin, TimestampMixin, Base):
    """Mwaliko wa kujiunga na organization."""

    __tablename__ = "invitations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    email: Mapped[str] = mapped_column(String(320), index=True, nullable=False)
    role: Mapped[Role] = mapped_column(
        SAEnum(Role, name="user_role", values_callable=lambda e: [m.value for m in e]),
        default=Role.VIEWER,
        nullable=False,
    )
    status: Mapped[InvitationStatus] = mapped_column(
        SAEnum(
            InvitationStatus,
            name="invitation_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        default=InvitationStatus.PENDING,
        index=True,
        nullable=False,
    )

    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    email_sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    organization: Mapped["Organization"] = relationship(back_populates="invitations")
    invited_by: Mapped["User | None"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Invitation {self.email} -> {self.role.value}>"
