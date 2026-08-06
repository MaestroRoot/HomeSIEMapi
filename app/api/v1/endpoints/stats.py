"""Takwimu zilizokusanywa kwa dashboard (Overview, Visualization)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession
from app.crud import stats as stats_crud
from app.schemas.stats import SecurityScore, StatsOverview

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/overview", response_model=StatsOverview, summary="Aggregated dashboard stats")
async def overview(user: CurrentUser, db: DbSession) -> StatsOverview:
    return await stats_crud.overview(db, user.organization_id)


@router.get("/score", response_model=SecurityScore, summary="Home security posture score")
async def score(user: CurrentUser, db: DbSession) -> SecurityScore:
    return await stats_crud.security_score(db, user.organization_id)
