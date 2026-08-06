"""Fixtures za tests.

Tests zinatumia database HALISI (container ya docker-compose) lakini kwenye
schema tofauti inayoitwa `test_<random>`, ambayo inafutwa mwishoni. Hii inaepusha
kuchafua data ya development na wakati huo huo inaturuhusu kupima enum types na
constraints za Postgres, vitu ambavyo SQLite isingeweza kuvipima.
"""

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio

# Dev bypass lazima iwashwe kabla `app.core.config` haijasomwa.
os.environ["AUTH_DEV_BYPASS"] = "true"
os.environ["ENV"] = "development"

from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.ratelimit import session_limiter  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402

TEST_SCHEMA = f"test_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(
        settings.database_url,
        poolclass=None,
        connect_args={"server_settings": {"search_path": TEST_SCHEMA}},
    )

    async with eng.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{TEST_SCHEMA}"'))
        await conn.run_sync(Base.metadata.create_all)

    yield eng

    async with eng.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA IF EXISTS "{TEST_SCHEMA}" CASCADE'))
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine) -> AsyncGenerator[AsyncSession, None]:
    maker = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with maker() as session:
        yield session


@pytest_asyncio.fixture
async def client(engine) -> AsyncGenerator[AsyncClient, None]:
    """TestClient yenye database ya test badala ya ile ya development."""
    maker = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    session_limiter.reset()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test/api/v1") as http:
        yield http

    app.dependency_overrides.clear()


def dev_auth(email: str, name: str | None = None) -> dict[str, str]:
    token = f"dev:{email}" + (f":{name}" if name else "")
    return {"Authorization": f"Bearer {token}"}
