import logging
from sqlalchemy import text
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
        try:
            await conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS base_score FLOAT NOT NULL DEFAULT 1.0;"))
        except Exception as e:
            logger.debug(f"DB alter table detection_rules base_score: {e}")

    try:
        from app.core.database import AsyncSessionLocal
        from app.services.process_chain_rule_service import ProcessChainRuleService
        async with AsyncSessionLocal() as session:
            service = ProcessChainRuleService(session)
            await service.seed_default_data()
    except Exception as e:
        logger.error(f"Failed to seed process chain default data: {e}", exc_info=True)

    logger.info("Database initialization complete.")

