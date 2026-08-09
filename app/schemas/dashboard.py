"""Schemas za custom dashboards."""

import uuid
from datetime import datetime

from pydantic import Field, field_serializer

from app.schemas.common import CamelModel


class WidgetPosition(CamelModel):
    x: int = 0
    y: int = 0
    w: int = 6
    h: int = 4


class WidgetRead(CamelModel):
    id: uuid.UUID
    dashboard_id: uuid.UUID
    widget_type: str
    title: str
    query: str | None = None
    config: dict = {}
    position: dict = {}
    sort_order: int = 0
    is_visible: bool = True
    created_at: datetime
    updated_at: datetime

    @field_serializer("id", "dashboard_id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class WidgetCreate(CamelModel):
    widget_type: str = Field(pattern=r"^(chart|table|single_value|map|alert_feed|metric_card)$")
    title: str = Field(min_length=1, max_length=200)
    query: str | None = None
    config: dict = {}
    position: dict = {}
    sort_order: int = 0
    is_visible: bool = True


class WidgetUpdate(CamelModel):
    widget_type: str | None = Field(default=None, pattern=r"^(chart|table|single_value|map|alert_feed|metric_card)$")
    title: str | None = Field(default=None, min_length=1, max_length=200)
    query: str | None = None
    config: dict | None = None
    position: dict | None = None
    sort_order: int | None = None
    is_visible: bool | None = None


class DashboardRead(CamelModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    created_by_id: uuid.UUID | None = None
    title: str
    description: str | None = None
    template: str | None = None
    visibility: str = "org"
    sort_order: int = 0
    is_default: bool = False
    config: dict = {}
    widgets: list[WidgetRead] = []
    created_at: datetime
    updated_at: datetime

    @field_serializer("id", "organization_id", "created_by_id")
    def _uuid_to_str(self, value: uuid.UUID | None) -> str | None:
        return str(value) if value else None


class DashboardCreate(CamelModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = None
    template: str | None = Field(default=None, pattern=r"^(executive|soc|network|endpoint)$")
    visibility: str = Field(default="org", pattern=r"^(private|org|public)$")
    sort_order: int = 0
    config: dict = {}
    widgets: list[WidgetCreate] = []


class DashboardUpdate(CamelModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    visibility: str | None = Field(default=None, pattern=r"^(private|org|public)$")
    sort_order: int | None = None
    is_default: bool | None = None
    config: dict | None = None


class DashboardList(CamelModel):
    items: list[DashboardRead]
    total: int
