import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import register_error_handlers
from app.core.firebase import init_firebase
from app.core.logging import configure_logging, get_logger
from app.core.scheduler import run_scheduler
from app.db.session import dispose_engine

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    init_firebase()
    logger.info("%s inaanza (env=%s)", settings.app_name, settings.env)
    if settings.dev_bypass_enabled:
        logger.warning("AUTH_DEV_BYPASS imewashwa, token 'dev:<email>' zinakubalika")

    stop_event = asyncio.Event()
    scheduler_task = asyncio.create_task(run_scheduler(stop_event))

    yield

    stop_event.set()
    try:
        await asyncio.wait_for(scheduler_task, timeout=5)
    except asyncio.TimeoutError:
        scheduler_task.cancel()
    await dispose_engine()
    logger.info("Server imesimama")


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Backend ya HomeSIEM, auth kupitia Firebase, data kwenye Postgres.",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_error_handlers(app)
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"name": settings.app_name, "docs": "/docs", "api": settings.api_v1_prefix}
