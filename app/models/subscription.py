import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum as SAEnum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import Plan, SubscriptionStatus

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.payment import Payment


class Subscription(UUIDMixin, TimestampMixin, Base):
    """Kifurushi kinachotumika sasa na org.

    Org ina subscription MOJA tu inayotumika kwa wakati mmoja, ndio maana
    `organization_id` ni unique. Historia ya malipo iko kwenye `payments`.
    """

    __tablename__ = "subscriptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    organization: Mapped["Organization"] = relationship(back_populates="subscription")

    plan: Mapped[Plan] = mapped_column(
        SAEnum(Plan, name="plan", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        SAEnum(
            SubscriptionStatus,
            name="subscription_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        default=SubscriptionStatus.ACTIVE,
        nullable=False,
    )

    #: Bei iliyokubaliwa wakati wa kujiunga. Tunaihifadhi ili kupanda kwa bei
    #: kusibadilishe kile mteja wa zamani anacholipa.
    price_tzs: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="TZS", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Mwisho wa siku 30 za Business anazopewa kila anayejisajili. Ikipita bila
    #: malipo, kifurushi kinashuka hadi Free.
    trial_ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    current_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    payments: Mapped[list["Payment"]] = relationship(
        back_populates="subscription", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Subscription {self.plan.value} {self.status.value}>"
