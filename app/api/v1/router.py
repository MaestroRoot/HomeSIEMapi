from fastapi import APIRouter

from app.api.v1.endpoints import (
    actions,
    admin,
    agent,
    ai,
    alerts,
    auth,
    capture,
    contact,
    dashboards,
    detection,
    devices,
    health,
    incidents,
    ingest,
    intel,
    inventory,
    invitations,
    nextdns,
    notifications,
    org,
    reports,
    sources,
    stats,
    subscriptions,
    telemetry,
    users,
)
from app.api.v1.endpoints import ueva

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(admin.router)
api_router.include_router(users.router)
api_router.include_router(invitations.router)
api_router.include_router(subscriptions.router)
api_router.include_router(reports.router)
api_router.include_router(intel.router)
api_router.include_router(capture.router)
api_router.include_router(devices.router)
api_router.include_router(ingest.router)
api_router.include_router(stats.router)
api_router.include_router(ai.router)
api_router.include_router(detection.router)
api_router.include_router(incidents.router)
api_router.include_router(telemetry.router)
api_router.include_router(agent.router)
api_router.include_router(notifications.router)
api_router.include_router(org.router)
api_router.include_router(inventory.router)
api_router.include_router(nextdns.router)
api_router.include_router(ueva.router)
api_router.include_router(dashboards.router)
api_router.include_router(contact.router, prefix="/contact", tags=["contact"])
api_router.include_router(sources.router)
api_router.include_router(alerts.router)
api_router.include_router(actions.router)
