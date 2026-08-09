"""API endpoints za custom dashboards."""

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.crud import dashboard as dash_crud
from app.schemas.dashboard import (
    DashboardCreate,
    DashboardList,
    DashboardRead,
    DashboardUpdate,
    WidgetCreate,
    WidgetRead,
    WidgetUpdate,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/dashboards", tags=["dashboards"])


@router.get("", response_model=DashboardList, summary="List all dashboards")
async def list_dashboards(
    user: CurrentUser,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> DashboardList:
    rows, total = await dash_crud.list_dashboards(
        db, user.organization_id, limit=limit, offset=offset
    )
    return DashboardList(
        items=[DashboardRead.model_validate(r) for r in rows], total=total
    )


@router.get("/{dashboard_id}", response_model=DashboardRead, summary="Get a dashboard")
async def get_dashboard(
    dashboard_id: str,
    user: CurrentUser,
    db: DbSession,
) -> DashboardRead:
    import uuid
    dashboard = await dash_crud.get_dashboard(db, uuid.UUID(dashboard_id), user.organization_id)
    if dashboard is None:
        raise NotFoundError("Dashboard not found.", code="dashboard_not_found")
    return DashboardRead.model_validate(dashboard)


@router.post("", response_model=DashboardRead, status_code=201, summary="Create a dashboard")
async def create_dashboard(
    payload: DashboardCreate,
    user: RequireAnalyst,
    db: DbSession,
) -> DashboardRead:
    dashboard = await dash_crud.create_dashboard(
        db,
        organization_id=user.organization_id,
        created_by_id=user.id,
        title=payload.title,
        description=payload.description,
        template=payload.template,
        visibility=payload.visibility,
        sort_order=payload.sort_order,
        config=payload.config,
        widgets=[w.model_dump() for w in payload.widgets] if payload.widgets else None,
    )
    logger.info("Dashboard created: %s by org=%s", dashboard.id, user.organization_id)
    return DashboardRead.model_validate(dashboard)


@router.put("/{dashboard_id}", response_model=DashboardRead, summary="Update a dashboard")
async def update_dashboard(
    dashboard_id: str,
    payload: DashboardUpdate,
    user: RequireAnalyst,
    db: DbSession,
) -> DashboardRead:
    import uuid
    dashboard = await dash_crud.get_dashboard(db, uuid.UUID(dashboard_id), user.organization_id)
    if dashboard is None:
        raise NotFoundError("Dashboard not found.", code="dashboard_not_found")
    updated = await dash_crud.update_dashboard(
        db, dashboard, **payload.model_dump(exclude_unset=True)
    )
    return DashboardRead.model_validate(updated)


@router.delete("/{dashboard_id}", status_code=204, summary="Delete a dashboard")
async def delete_dashboard(
    dashboard_id: str,
    user: RequireAnalyst,
    db: DbSession,
) -> None:
    import uuid
    dashboard = await dash_crud.get_dashboard(db, uuid.UUID(dashboard_id), user.organization_id)
    if dashboard is None:
        raise NotFoundError("Dashboard not found.", code="dashboard_not_found")
    await dash_crud.delete_dashboard(db, dashboard)
    logger.info("Dashboard deleted: %s", dashboard_id)


# --- Widgets ---------------------------------------------------------------

@router.post("/{dashboard_id}/widgets", response_model=WidgetRead, status_code=201, summary="Add a widget")
async def add_widget(
    dashboard_id: str,
    payload: WidgetCreate,
    user: RequireAnalyst,
    db: DbSession,
) -> WidgetRead:
    import uuid
    dashboard = await dash_crud.get_dashboard(db, uuid.UUID(dashboard_id), user.organization_id)
    if dashboard is None:
        raise NotFoundError("Dashboard not found.", code="dashboard_not_found")
    widget = await dash_crud.add_widget(
        db,
        dashboard_id=dashboard.id,
        widget_type=payload.widget_type,
        title=payload.title,
        query=payload.query,
        config=payload.config,
        position=payload.position,
        sort_order=payload.sort_order,
        is_visible=payload.is_visible,
    )
    return WidgetRead.model_validate(widget)


@router.put("/{dashboard_id}/widgets/{widget_id}", response_model=WidgetRead, summary="Update a widget")
async def update_widget(
    dashboard_id: str,
    widget_id: str,
    payload: WidgetUpdate,
    user: RequireAnalyst,
    db: DbSession,
) -> WidgetRead:
    import uuid
    from sqlalchemy import select
    from app.models.dashboard import DashboardWidget
    stmt = select(DashboardWidget).where(
        DashboardWidget.id == uuid.UUID(widget_id),
        DashboardWidget.dashboard_id == uuid.UUID(dashboard_id),
    )
    widget = (await db.execute(stmt)).scalar_one_or_none()
    if widget is None:
        raise NotFoundError("Widget not found.", code="widget_not_found")
    updated = await dash_crud.update_widget(
        db, widget, **payload.model_dump(exclude_unset=True)
    )
    return WidgetRead.model_validate(updated)


@router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=204, summary="Delete a widget")
async def delete_widget(
    dashboard_id: str,
    widget_id: str,
    user: RequireAnalyst,
    db: DbSession,
) -> None:
    import uuid
    from sqlalchemy import select
    from app.models.dashboard import DashboardWidget
    stmt = select(DashboardWidget).where(
        DashboardWidget.id == uuid.UUID(widget_id),
        DashboardWidget.dashboard_id == uuid.UUID(dashboard_id),
    )
    widget = (await db.execute(stmt)).scalar_one_or_none()
    if widget is None:
        raise NotFoundError("Widget not found.", code="widget_not_found")
    await dash_crud.delete_widget(db, widget)
