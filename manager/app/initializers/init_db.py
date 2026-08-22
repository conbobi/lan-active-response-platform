import logging
from app.core.database import async_engine
from app.models.base import Base
# Import all models to ensure they are registered with Base.metadata
import app.models  # noqa: F401

logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Initialize database tables asynchronously."""
    async with async_engine.begin() as conn:
        logger.info("Creating database tables if they do not exist...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialization complete.")
