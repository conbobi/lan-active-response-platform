"""Add threat_memory and threat_memory_events (AI Threat Memory)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a4b5c6d7e8f9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None

J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("threat_memory"):
        op.create_table(
            "threat_memory",
            sa.Column("id", sa.String(40), primary_key=True),
            sa.Column("tenant", sa.String(64), nullable=False),
            sa.Column("fingerprint", sa.String(64), nullable=False),
            sa.Column("fingerprint_version", sa.String(16), nullable=False),
            sa.Column("attack_pattern", sa.String(160), nullable=False),
            sa.Column("platform", sa.String(16), nullable=False),
            sa.Column("detection_rule_ids", J, nullable=False),
            sa.Column("mitre_techniques", J, nullable=False),
            sa.Column("behavioral_features", J, nullable=False),
            sa.Column("analysis_template", J, nullable=False),
            sa.Column("response_playbook_reference", J, nullable=False),
            sa.Column("evidence_requirements", J, nullable=False),
            sa.Column("model_name", sa.String(128), nullable=False),
            sa.Column("prompt_version", sa.String(64), nullable=False),
            sa.Column("telemetry_schema_version", sa.String(32), nullable=False),
            sa.Column("validation_status", sa.String(24), nullable=False),
            sa.Column("status_reason", sa.String(255), nullable=True),
            sa.Column("reviewer", sa.String(128), nullable=True),
            sa.Column("source_incident_id", sa.String(64), nullable=True),
            sa.Column("created_at", TS, nullable=False),
            sa.Column("updated_at", TS, nullable=False),
            sa.Column("expires_at", TS, nullable=False),
            sa.Column("last_used_at", TS, nullable=True),
            sa.Column("usage_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("quality_score", sa.Float(), nullable=False, server_default="0.6"),
            sa.UniqueConstraint("tenant", "fingerprint", "fingerprint_version", "prompt_version", "model_name",
                                name="uq_threat_memory_fingerprint"),
        )
        op.create_index("ix_threat_memory_lookup", "threat_memory",
                        ["tenant", "platform", "fingerprint_version", "validation_status"])
    if not inspector.has_table("threat_memory_events"):
        op.create_table(
            "threat_memory_events",
            sa.Column("id", sa.String(40), primary_key=True),
            sa.Column("request_id", sa.String(40), nullable=False),
            sa.Column("incident_id", sa.String(64), nullable=True),
            sa.Column("decision", sa.String(24), nullable=False),
            sa.Column("memory_id", sa.String(40), nullable=True),
            sa.Column("reason", sa.String(64), nullable=True),
            sa.Column("stale_rejected", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("lookup_error", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("lookup_ms", sa.Float(), nullable=True),
            sa.Column("llm_ms", sa.Float(), nullable=True),
            sa.Column("total_ms", sa.Float(), nullable=True),
            sa.Column("tokens", sa.Integer(), nullable=True),
            sa.Column("created_at", TS, nullable=False),
        )
        op.create_index("ix_threat_memory_events_created", "threat_memory_events", ["created_at"])


def downgrade():
    op.drop_table("threat_memory_events")
    op.drop_table("threat_memory")
