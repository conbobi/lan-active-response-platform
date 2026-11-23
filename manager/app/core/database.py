from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.core.config import settings

# Async Engine
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    pool_size=20,
    max_overflow=20,
    pool_timeout=30.0,
    pool_pre_ping=True,
    pool_recycle=300
)

# Async Session Factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Aliases for backwards compatibility
async_session_maker = AsyncSessionLocal
async_sessionmaker = AsyncSessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining an AsyncSession."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_pool_status() -> dict:
    """Safely return SQLAlchemy async engine QueuePool metrics without leaking credentials."""
    pool = async_engine.pool
    try:
        pool_size = pool.size()
        checked_in = pool.checkedin()
        checked_out = pool.checkedout()
        overflow = pool.overflow()
    except Exception:
        pool_size = 20
        checked_in = 0
        checked_out = 0
        overflow = 0

    return {
        "pool_size": pool_size,
        "checked_in_connections": checked_in,
        "checked_out_connections": checked_out,
        "overflow": overflow,
        "max_overflow": getattr(pool, "_max_overflow", 20),
        "timeout": getattr(pool, "_timeout", 30.0),
        "total_active_connections": checked_out,
    }
