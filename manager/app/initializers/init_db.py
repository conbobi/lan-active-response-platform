import logging
from sqlalchemy import inspect, text
from app.core.database import async_engine
from app.models.base import Base
# Import all models to ensure they are registered with Base.metadata
import app.models  # noqa: F401

logger = logging.getLogger(__name__)


def ensure_process_instance_column(connection):
    if connection.dialect.name == "postgresql":
        connection.execute(text("ALTER TABLE process_info ADD COLUMN IF NOT EXISTS process_start_time DOUBLE PRECISION"))
        return
    columns = inspect(connection).get_columns("process_info")
    if all(column["name"] != "process_start_time" for column in columns):
        connection.execute(text("ALTER TABLE process_info ADD COLUMN process_start_time DOUBLE PRECISION"))


def ensure_network_evidence_columns(connection):
    if connection.dialect.name == "postgresql":
        connection.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detection_evidence JSON"))
        connection.execute(text("ALTER TABLE flows ADD COLUMN IF NOT EXISTS socket_evidence JSON"))
        return
    inspector = inspect(connection)
    for table, name in (("incidents", "detection_evidence"), ("flows", "socket_evidence")):
        if not any(column["name"] == name for column in inspector.get_columns(table)):
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} JSON"))


def ensure_activity_schema(connection):
    inspector = inspect(connection)
    datetime_type = "TIMESTAMP WITH TIME ZONE" if connection.dialect.name == "postgresql" else "DATETIME"
    for table, column, datatype in (
        ("agents", "decommissioned_at", datetime_type),
        ("incidents", "fingerprint", "VARCHAR(64)"),
    ):
        if connection.dialect.name == "postgresql":
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {datatype}"))
        elif not any(field["name"] == column for field in inspector.get_columns(table)):
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {datatype}"))
    app.models.AgentActivity.__table__.create(connection, checkfirst=True)
    for index in app.models.Incident.__table__.indexes:
        index.create(connection, checkfirst=True)


def ensure_ai_run_schema(connection):
    """Reasoning Orchestrator runs (Rule Generator, Risk Analyst questions) on a table created before them."""
    inspector = inspect(connection)
    if not inspector.has_table("ai_analysis_runs"):
        return  # create_all made it with the current columns
    postgres = connection.dialect.name == "postgresql"
    columns = (("task_type", "VARCHAR(32) NOT NULL DEFAULT 'incident_analysis'"), ("subject_id", "VARCHAR(64)"),
               ("question", "TEXT"), ("result", "JSONB" if postgres else "JSON"), ("current_stage", "VARCHAR(48)"),
               ("stage_status", "VARCHAR(24)"))
    existing = {c["name"] for c in inspector.get_columns("ai_analysis_runs")}
    for name, datatype in columns:
        if postgres:
            connection.execute(text(f"ALTER TABLE ai_analysis_runs ADD COLUMN IF NOT EXISTS {name} {datatype}"))
        elif name not in existing:
            connection.execute(text(f"ALTER TABLE ai_analysis_runs ADD COLUMN {name} {datatype}"))
    if postgres:  # Rule Generator runs belong to a conversation, not to an incident
        connection.execute(text("ALTER TABLE ai_analysis_runs ALTER COLUMN incident_id DROP NOT NULL"))
        connection.execute(text("ALTER TABLE ai_decision_trace_events ALTER COLUMN incident_id DROP NOT NULL"))
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_ai_analysis_runs_task_subject "
                            "ON ai_analysis_runs (task_type, subject_id)"))


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
            await conn.execute(text("ALTER TABLE risk_score_records ADD COLUMN IF NOT EXISTS smoothed_score FLOAT DEFAULT 0.0;"))
        except Exception as e:
            logger.debug(f"DB alter table risk_score_records smoothed_score: {e}")
        try:
            await conn.execute(text("ALTER TABLE incidents ADD COLUMN notes TEXT;"))
        except Exception as e:
            logger.debug(f"DB alter table incidents notes: {e}")
        try:
            await conn.execute(text("ALTER TABLE incidents ADD COLUMN resolved_at DATETIME;"))
        except Exception as e:
            logger.debug(f"DB alter table incidents resolved_at: {e}")

    try:
        from app.core.database import AsyncSessionLocal
        from app.services.detection.process_chain_rule_service import ProcessChainRuleService
        async with AsyncSessionLocal() as session:
            service = ProcessChainRuleService(session)
            await service.seed_default_data()
    except Exception as e:
        logger.error(f"Failed to seed process chain default data: {e}", exc_info=True)

    logger.info("Database initialization complete.")

