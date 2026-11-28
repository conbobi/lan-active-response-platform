"""Add ai_analysis_runs and ai_decision_trace_events for AI Risk Analyst Decision Trace."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d8e9f0a1b2c3"
down_revision = "c72d6e1f037a"
branch_labels = None
depends_on = None

J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("ai_analysis_runs"):
        op.create_table(
            "ai_analysis_runs",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("incident_id", sa.String(64), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("requested_by", sa.String(128), nullable=False, server_default="system"),
            sa.Column("mode", sa.String(24), nullable=False, server_default="reuse"),
            sa.Column("status", sa.String(24), nullable=False, server_default="CREATED"),
            sa.Column("evidence_version", sa.String(64), nullable=True),
            sa.Column("analysis_id", sa.String(64), nullable=True),
            sa.Column("model_name", sa.String(64), nullable=True),
            sa.Column("error_code", sa.String(64), nullable=True),
            sa.Column("error_message", sa.String(512), nullable=True),
            sa.Column("started_at", TS, nullable=True),
            sa.Column("completed_at", TS, nullable=True),
            sa.Column("created_at", TS, nullable=False),
        )
        op.create_index("ix_ai_analysis_runs_incident_created", "ai_analysis_runs", ["incident_id", "created_at"])

    if not inspector.has_table("ai_decision_trace_events"):
        op.create_table(
            "ai_decision_trace_events",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("analysis_run_id", sa.String(64), sa.ForeignKey("ai_analysis_runs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=False),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("event_type", sa.String(32), nullable=False),
            sa.Column("stage", sa.String(48), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("source_type", sa.String(32), nullable=False, server_default="DETERMINISTIC"),
            sa.Column("started_at", TS, nullable=True),
            sa.Column("completed_at", TS, nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("evidence_refs", J, nullable=False),
            sa.Column("rule_refs", J, nullable=False),
            sa.Column("safe_result", J, nullable=True),
            sa.Column("error_code", sa.String(64), nullable=True),
            sa.Column("created_at", TS, nullable=False),
            sa.UniqueConstraint("analysis_run_id", "sequence", name="uq_ai_trace_run_seq"),
        )
        op.create_index("ix_ai_trace_events_run_seq", "ai_decision_trace_events", ["analysis_run_id", "sequence"])
        op.create_index("ix_ai_decision_trace_events_incident", "ai_decision_trace_events", ["incident_id"])


def downgrade():
    op.drop_table("ai_decision_trace_events")
    op.drop_table("ai_analysis_runs")

