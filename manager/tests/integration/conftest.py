import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text
from sqlalchemy.pool import NullPool
from httpx import AsyncClient, ASGITransport
from fastapi.testclient import TestClient

from app.main import app as fastapi_app
from app.core.deps import get_db
from app.models.base import Base
import app.models  # noqa: F401

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://larp:larp_password@localhost:5432/larpdb"
)

test_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    poolclass=NullPool
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    """Clean all tables before each test to guarantee isolated real-database test state."""
    async with TestSessionLocal() as session:
        if "postgresql" in DATABASE_URL:
            table_names = [table.name for table in reversed(Base.metadata.sorted_tables)]
            if table_names:
                tables_str = ", ".join(f'"{name}"' for name in table_names)
                await session.execute(text(f"TRUNCATE TABLE {tables_str} CASCADE;"))
        else:
            for table in reversed(Base.metadata.sorted_tables):
                await session.execute(table.delete())
        await session.commit()


@pytest_asyncio.fixture
async def db_session():
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
def test_app():
    async def _override_get_db():
        async with TestSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    fastapi_app.dependency_overrides[get_db] = _override_get_db
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
def test_client(test_app):
    return TestClient(test_app)