"""CRUD operations za custom dashboards."""

import uuid
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dashboard import Dashboard, DashboardWidget


async def list_dashboards(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Dashboard], int]:
    total = await db.scalar(
        select(func.count(Dashboard.id)).where(Dashboard.organization_id == organization_id)
    )
    stmt = (
        select(Dashboard)
        .where(Dashboard.organization_id == organization_id)
        .options(selectinload(Dashboard.widgets))
        .order_by(Dashboard.sort_order, Dashboard.created_at)
        .limit(limit)
        .offset(offset)
    )
    rows = list((await db.execute(stmt)).scalars().unique())
    return rows, int(total or 0)


async def get_dashboard(db: AsyncSession, dashboard_id: uuid.UUID, organization_id: uuid.UUID) -> Dashboard | None:
    stmt = (
        select(Dashboard)
        .where(Dashboard.id == dashboard_id, Dashboard.organization_id == organization_id)
        .options(selectinload(Dashboard.widgets))
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_dashboard(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    created_by_id: uuid.UUID | None,
    title: str,
    description: str | None = None,
    template: str | None = None,
    visibility: str = "org",
    sort_order: int = 0,
    config: dict | None = None,
    widgets: list[dict] | None = None,
) -> Dashboard:
    dashboard = Dashboard(
        organization_id=organization_id,
        created_by_id=created_by_id,
        title=title,
        description=description,
        template=template,
        visibility=visibility,
        sort_order=sort_order,
        config=config or {},
    )
    db.add(dashboard)
    await db.flush()

    for i, w in enumerate(widgets or []):
        widget = DashboardWidget(
            dashboard_id=dashboard.id,
            widget_type=w.get("widget_type", "chart"),
            title=w.get("title", "Untitled"),
            query=w.get("query"),
            config=w.get("config", {}),
            position=w.get("position", {}),
            sort_order=w.get("sort_order", i),
            is_visible=w.get("is_visible", True),
        )
        db.add(widget)

    await db.commit()
    await db.refresh(dashboard)
    # Reload with widgets
    return await get_dashboard(db, dashboard.id, organization_id) or dashboard


async def update_dashboard(
    db: AsyncSession,
    dashboard: Dashboard,
    **fields,
) -> Dashboard:
    for key, value in fields.items():
        if value is not None and hasattr(dashboard, key):
            setattr(dashboard, key, value)
    await db.commit()
    await db.refresh(dashboard)
    return await get_dashboard(db, dashboard.id, dashboard.organization_id) or dashboard


async def delete_dashboard(db: AsyncSession, dashboard: Dashboard) -> None:
    await db.delete(dashboard)
    await db.commit()


async def add_widget(
    db: AsyncSession,
    *,
    dashboard_id: uuid.UUID,
    widget_type: str,
    title: str,
    query: str | None = None,
    config: dict | None = None,
    position: dict | None = None,
    sort_order: int = 0,
    is_visible: bool = True,
) -> DashboardWidget:
    widget = DashboardWidget(
        dashboard_id=dashboard_id,
        widget_type=widget_type,
        title=title,
        query=query,
        config=config or {},
        position=position or {},
        sort_order=sort_order,
        is_visible=is_visible,
    )
    db.add(widget)
    await db.commit()
    await db.refresh(widget)
    return widget


async def update_widget(
    db: AsyncSession,
    widget: DashboardWidget,
    **fields,
) -> DashboardWidget:
    for key, value in fields.items():
        if value is not None and hasattr(widget, key):
            setattr(widget, key, value)
    await db.commit()
    await db.refresh(widget)
    return widget


async def delete_widget(db: AsyncSession, widget: DashboardWidget) -> None:
    await db.delete(widget)
    await db.commit()
