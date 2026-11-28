"""Generalize ai_analysis_runs into Reasoning Orchestrator runs (Rule Generator, Risk Analyst questions)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e1f2a3b4c5d6"
down_revision = "d8e9f0a1b2c3"
branch_labels = None
depends_on = None

J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
COLUMNS = (
    sa.Column("task_type", sa.String(32), nullable=False, server_default="incident_analysis"),
    sa.Column("subject_id", sa.String(64), nullable=True),
    sa.Column("question", sa.Text(), nullable=True),
    sa.Column("result", J, nullable=True),
    sa.Column("current_stage", sa.String(48), nullable=True),
    sa.Column("stage_status", sa.String(24), nullable=True),
)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing = {c["name"] for c in inspector.get_columns("ai_analysis_runs")}
    with op.batch_alter_table("ai_analysis_runs") as batch:
        for column in COLUMNS:
            if column.name not in existing:
                batch.add_column(column.copy())
        batch.alter_column("incident_id", existing_type=sa.String(64), nullable=True)
    with op.batch_alter_table("ai_decision_trace_events") as batch:
        batch.alter_column("incident_id", existing_type=sa.String(64), nullable=True)
    indexes = {i["name"] for i in inspector.get_indexes("ai_analysis_runs")}
    if "ix_ai_analysis_runs_task_subject" not in indexes:
        op.create_index("ix_ai_analysis_runs_task_subject", "ai_analysis_runs", ["task_type", "subject_id"])


def downgrade():
    op.drop_index("ix_ai_analysis_runs_task_subject", table_name="ai_analysis_runs")
    op.execute("DELETE FROM ai_analysis_runs WHERE incident_id IS NULL")
    with op.batch_alter_table("ai_decision_trace_events") as batch:
        batch.alter_column("incident_id", existing_type=sa.String(64), nullable=False)
    with op.batch_alter_table("ai_analysis_runs") as batch:
        batch.alter_column("incident_id", existing_type=sa.String(64), nullable=False)
        for column in reversed(COLUMNS):
            batch.drop_column(column.name)
