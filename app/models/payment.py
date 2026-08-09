import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.enums import PaymentChannel, PaymentMethod, PaymentStatus, Plan

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.subscription import Subscription
    from app.models.user import User


class Payment(UUIDMixin, TimestampMixin, Base):
    """Jaribio moja la malipo.

    HATARI YA PCI: table hii HAIHIFADHI namba kamili ya card, expiry wala CVV,
    na haitawahi. Card inapita moja kwa moja kwa payment gateway,
    sisi tunabaki na `card_last4` + `card_brand` kwa ajili ya kumkumbusha mteja
    alilipa kwa card ipi. Kwa mobile money tunahifadhi namba ya simu kwa sababu
    ndiyo kitambulisho cha muamala, sio siri ya malipo.
    """

    __tablename__ = "payments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("subscriptions.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    initiated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    plan: Mapped[Plan] = mapped_column(
        SAEnum(Plan, name="plan", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    amount_tzs: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="TZS", nullable=False)

    method: Mapped[PaymentMethod] = mapped_column(
        SAEnum(
            PaymentMethod,
            name="payment_method",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    channel: Mapped[PaymentChannel] = mapped_column(
        SAEnum(
            PaymentChannel,
            name="payment_channel",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    status: Mapped[PaymentStatus] = mapped_column(
        SAEnum(
            PaymentStatus,
            name="payment_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        default=PaymentStatus.PENDING,
        index=True,
        nullable=False,
    )

    #: Mobile money pekee. E.164 bila alama, mfano 255712345678.
    msisdn: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: Card pekee, na ni tarakimu 4 za mwisho TU.
    card_last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    card_brand: Mapped[str | None] = mapped_column(String(20), nullable=True)

    #: Reference yetu tunayompa gateway, unique ili retry isilipe mara mbili.
    reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    #: Reference inayotoka gateway ikishajibu.
    provider_reference: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    provider: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)

    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship(back_populates="payments")
    subscription: Mapped["Subscription | None"] = relationship(back_populates="payments")
    initiated_by: Mapped["User | None"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Payment {self.reference} {self.amount_tzs} {self.status.value}>"
