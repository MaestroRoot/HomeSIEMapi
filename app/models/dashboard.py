"""Models za custom dashboards — user anaweza kutengeneza dashboards zake."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class Dashboard(UUIDMixin, TimestampMixin, Base):
    """Dashboard inayotengenezwa na mtumiaji."""

    __tablename__ = "dashboards"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: template: "executive", "soc", "network", "endpoint", au None (custom)
    template: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Sera ya upatikanaji: "private" | "org" | "public"
    visibility: Mapped[str] = mapped_column(String(16), default="org", nullable=False)
    #: Sura kwenye sidebar, 0 = ya kwanza
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Vipengele vya dashboard kama JSON (grid size, etc.)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    organization: Mapped["Organization"] = relationship(back_populates="dashboards")
    created_by: Mapped["User | None"] = relationship()
    widgets: Mapped[list["DashboardWidget"]] = relationship(
        back_populates="dashboard", cascade="all, delete-orphan", order_by="DashboardWidget.sort_order"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Dashboard {self.title}>"


class DashboardWidget(UUIDMixin, TimestampMixin, Base):
    """Widget ndani ya dashboard — kila widget ni chart, table, single value, n.k."""

    __tablename__ = "dashboard_widgets"

    dashboard_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("dashboards.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    #: "chart" | "table" | "single_value" | "map" | "alert_feed" | "metric_card"
    widget_type: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Query / filter ya widget hii (SIEM query language yetu)
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Config maalum ya widget (chart type, columns, thresholds, n.k.)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Nafasi kwenye grid: {"x": 0, "y": 0, "w": 6, "h": 4}
    position: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_visible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    dashboard: Mapped["Dashboard"] = relationship(back_populates="widgets")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DashboardWidget {self.title} ({self.widget_type})>"
