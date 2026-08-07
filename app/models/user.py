import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import Plan, Role

if TYPE_CHECKING:
    from app.models.organization import Organization


class User(UUIDMixin, TimestampMixin, Base):
    """Mtumiaji wetu.

    MUHIMU: password HAIPO hapa na haitawahi kuwepo, Firebase ndio inashikilia
    credentials. Sisi tunashikilia `firebase_uid` pekee kama kiungo, pamoja na
    authorization (role, plan, org) ambayo backend inaamini.
    """

    __tablename__ = "users"

    firebase_uid: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(30), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    role: Mapped[Role] = mapped_column(
        SAEnum(Role, name="user_role", values_callable=lambda e: [m.value for m in e]),
        default=Role.VIEWER,
        nullable=False,
    )
    plan: Mapped[Plan] = mapped_column(
        SAEnum(Plan, name="plan", values_callable=lambda e: [m.value for m in e]),
        default=Plan.FREE,
        nullable=False,
    )

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(128), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    organization: Mapped["Organization"] = relationship(back_populates="users")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} ({self.role.value})>"
