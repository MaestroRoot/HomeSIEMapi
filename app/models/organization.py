from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import Plan

if TYPE_CHECKING:
    from app.models.dashboard import Dashboard
    from app.models.payment import Payment
    from app.models.security import Invitation
    from app.models.subscription import Subscription
    from app.models.user import User


class Organization(UUIDMixin, TimestampMixin, Base):
    """Kila user yuko kwenye org. Sasa hivi ni org moja kwa kila mtu (aliyejisajili = owner),
    lakini table hii inaruhusu team/multi-tenant bila migration kubwa baadaye."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    plan: Mapped[Plan] = mapped_column(
        SAEnum(Plan, name="plan", values_callable=lambda e: [m.value for m in e]),
        default=Plan.FREE,
        nullable=False,
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    subscription: Mapped["Subscription | None"] = relationship(
        back_populates="organization", cascade="all, delete-orphan", uselist=False
    )
    payments: Mapped[list["Payment"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    invitations: Mapped[list["Invitation"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    dashboards: Mapped[list["Dashboard"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Organization {self.slug}>"
