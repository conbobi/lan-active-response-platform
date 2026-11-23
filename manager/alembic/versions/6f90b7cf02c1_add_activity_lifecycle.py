"""Persist current observations and incident correlation identity."""

from alembic import op
from sqlalchemy import inspect

from app.initializers.init_db import ensure_activity_schema

revision = "6f90b7cf02c1"
down_revision = "2cf5cedde42e"
branch_labels = None
depends_on = None


def upgrade():
    ensure_activity_schema(op.get_bind())


def downgrade():
    inspector = inspect(op.get_bind())
    if inspector.has_table("agent_activity"):
        op.drop_table("agent_activity")
    op.drop_index("ix_incidents_agent_fingerprint_updated", table_name="incidents")
    op.drop_index("ix_incidents_status_created", table_name="incidents")
    op.drop_column("incidents", "fingerprint")
    op.drop_column("agents", "decommissioned_at")
