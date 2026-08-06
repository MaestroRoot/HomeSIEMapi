"""Worker ndogo ya ratiba: inatuma scheduled reports zilizofikia wakati.

Inaendesha ndani ya event loop ya app (imeanzishwa kwenye lifespan). Kila
dakika inachunguza `report_schedules`; ikipata iliyofikia wakati, inaijenga na
kuituma, kisha inaweka `next_run_at`.
"""

from __future__ import annotations

import asyncio

from app.core.logging import get_logger
from app.core.report_builder import send_report_now
from app.crud import agent as agent_crud
from app.crud import inventory as inv_crud
from app.crud import report_schedule as sched_crud
from app.db.session import AsyncSessionLocal

logger = get_logger(__name__)

_CHECK_SECONDS = 60


async def _tick_discovery() -> None:
    """Tuma discovery job kwa agent kwa kila ratiba iliyofikia wakati."""
    async with AsyncSessionLocal() as db:
        due = await inv_crud.due_schedules(db)
        for sched in due:
            try:
                params = {"subnet": sched.subnet} if sched.subnet else {}
                await agent_crud.create_job(
                    db, sched.organization_id, sched.agent_id, kind="discovery", params=params
                )
                await inv_crud.mark_ran(db, sched)
                logger.info("Discovery job imepangwa (org=%s, agent=%s)", sched.organization_id, sched.agent_id)
            except Exception as exc:  # noqa: BLE001
                logger.error("Discovery schedule imeshindwa: %s", exc)
                try:
                    await inv_crud.mark_ran(db, sched)
                except Exception:  # noqa: BLE001
                    await db.rollback()


async def _tick() -> None:
    async with AsyncSessionLocal() as db:
        due = await sched_crud.due_schedules(db)
        for sched in due:
            try:
                period = f"{sched.frequency} report"
                sent, failed = await send_report_now(
                    db,
                    sched.organization_id,
                    kind=sched.kind,
                    period=period,
                    recipients=list(sched.recipients or []),
                    to_whole_team=sched.to_whole_team,
                )
                await sched_crud.mark_ran(db, sched)
                logger.info("Scheduled report imetumwa: sent=%s failed=%s (org=%s)", len(sent), len(failed), sched.organization_id)
            except Exception as exc:  # noqa: BLE001
                logger.error("Scheduled report imeshindwa: %s", exc)
                # Songesha mbele ili isijaribu bila kikomo.
                try:
                    await sched_crud.mark_ran(db, sched)
                except Exception:  # noqa: BLE001
                    await db.rollback()


async def run_scheduler(stop: asyncio.Event) -> None:
    logger.info("Report scheduler imeanza (kila %ss)", _CHECK_SECONDS)
    while not stop.is_set():
        try:
            await _tick()
        except Exception as exc:  # noqa: BLE001
            logger.error("Scheduler tick error: %s", exc)
        try:
            await _tick_discovery()
        except Exception as exc:  # noqa: BLE001
            logger.error("Discovery tick error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_CHECK_SECONDS)
        except asyncio.TimeoutError:
            pass
    logger.info("Report scheduler imesimama")
