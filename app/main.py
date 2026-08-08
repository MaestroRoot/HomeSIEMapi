import asyncio
import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.errors import register_error_handlers
from app.core.firebase import init_firebase
from app.core.logging import configure_logging, get_logger
from app.core.scheduler import run_scheduler
from app.core.nextdns_poller import run_nextdns_poller
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
    nextdns_task = asyncio.create_task(run_nextdns_poller(stop_event))

    yield

    stop_event.set()
    for task in (scheduler_task, nextdns_task):
        try:
            await asyncio.wait_for(task, timeout=5)
        except asyncio.TimeoutError:
            task.cancel()
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
    expose_headers=["ETag"],
)


@app.middleware("http")
async def etag_middleware(request: Request, call_next):
    """ETag + 304 kwa GET za JSON. Data isipobadilika, client (yenye
    If-None-Match) inapata 304 bila body — muhimu kwenye mtandao wa polepole."""
    response = await call_next(request)
    if request.method != "GET" or response.status_code != 200:
        return response
    if not response.headers.get("content-type", "").startswith("application/json"):
        return response

    body = b""
    async for chunk in response.body_iterator:  # type: ignore[attr-defined]
        body += chunk
    etag = 'W/"%s"' % hashlib.sha1(body).hexdigest()[:20]

    def _carry(dst: Response) -> None:
        for key, value in response.headers.items():
            if key.lower() not in ("content-length", "content-type"):
                dst.headers[key] = value
        dst.headers["ETag"] = etag

    if request.headers.get("if-none-match") == etag:
        not_modified = Response(status_code=304)
        _carry(not_modified)
        return not_modified

    fresh = Response(content=body, status_code=200, media_type="application/json")
    _carry(fresh)
    return fresh


register_error_handlers(app)
app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"name": settings.app_name, "docs": "/docs", "api": settings.api_v1_prefix}
