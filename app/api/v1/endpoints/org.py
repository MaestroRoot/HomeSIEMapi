from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

import app.models  # noqa: F401  # inahakikisha kila table imesajiliwa kwenye Base.metadata

from app.api.deps import DbSession, RequireOwner
from app.api.v1.endpoints.nextdns import delete_profile
from app.core.errors import ServiceUnavailableError
from app.core.logging import get_logger
from app.crud import nextdns as nextdns_crud
from app.db.base import Base
from app.schemas.common import CamelModel

logger = get_logger(__name__)

router = APIRouter(prefix="/organization", tags=["organization"])

#: Tables ambazo rows zake ni za workspace moja. `users` na `organizations`
#: wanabaki — account ya mtu na org yenyewe ndio kifungo cha mfumo.
_SCOPED_TABLES = [
    table
    for table in Base.metadata.sorted_tables
    if "organization_id" in table.c and table.name not in ("users", "organizations")
]


class WipeResult(CamelModel):
    detail: str
    code: str
    deleted: dict[str, int]


@router.delete(
    "/data",
    response_model=WipeResult,
    summary="Delete all SIEM data for this workspace",
)
async def wipe_org_data(user: RequireOwner, db: DbSession) -> WipeResult:
    """Owner pekee anaweza kufuta data ZOTE za org: events, devices, agents,
    scans, findings, rules, schedules, n.k.

    Account za watu na organization zinabaki. Subscription inajitengeneza
    upya (kwenye Free plan) mara tu itakapohitajika.
    """
    deleted: dict[str, int] = {}
    try:
        for table in _SCOPED_TABLES:
            result = await db.execute(
                text(f'DELETE FROM "{table.name}" WHERE organization_id = :org_id'),
                {"org_id": user.organization_id},
            )
            deleted[table.name] = result.rowcount
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        logger.error("Wiping org data failed: org=%s error=%s", user.organization_id, exc)
        raise ServiceUnavailableError(
            "The database is unavailable right now.", code="database_unavailable"
        ) from exc

    # Futa pia profile ya NextDNS ya org hii (best-effort) ili isiwe orphan kwenye API.
    try:
        cfg = await nextdns_crud.get_for_org(db, user.organization_id)
        if cfg is not None and cfg.profile_id:
            await delete_profile(cfg.profile_id)
            logger.info("NextDNS profile deleted during wipe (org=%s, profile=%s)", user.organization_id, cfg.profile_id)
    except Exception as exc:  # noqa: BLE001  # wipe haipaswi kuvunjika kwa external call
        logger.warning("NextDNS profile cleanup during wipe imeshindwa: %s", exc)

    logger.warning(
        "Org data wiped: org=%s by=%s deleted=%s",
        user.organization_id,
        user.email,
        deleted,
    )
    return WipeResult(
        detail="All SIEM data has been deleted.",
        code="org_data_wiped",
        deleted={k: v for k, v in deleted.items() if v},
    )
