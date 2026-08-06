from fastapi import APIRouter

from app.core.config import settings
from app.core.firebase import admin_available, firebase_available
from app.db.session import ping_database

router = APIRouter(tags=["health"])


@router.get("/health", summary="Server health")
async def health() -> dict[str, object]:
    """Haihitaji auth. Inaonyesha ni sehemu zipi ziko tayari."""
    db_ok = await ping_database()
    return {
        "status": "ok",
        "app": settings.app_name,
        "env": settings.env,
        "checks": {
            "database": db_ok,
            "firebase": firebase_available(),
            # Service account, inahitajika kwa revocation pekee.
            "firebaseAdmin": admin_available(),
            "groq": settings.groq_enabled,
            "otx": settings.otx_enabled,
            "geoip": settings.geoip_enabled,
            "tshark": settings.tshark_available,
            "email": settings.email_enabled,
            "devAuthBypass": settings.dev_bypass_enabled,
        },
    }
