"""Add the exact AI analysis cache and reviewed incident pattern cases."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b7e4c2a91d35"
down_revision = "6f90b7cf02c1"
branch_labels = None
depends_on = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade():
    # Manager also creates these tables during normal startup (Base.metadata.create_all).
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("ai_analysis_cache"):
        op.create_table(
            "ai_analysis_cache",
            sa.Column("cache_key", sa.String(64), primary_key=True),
            sa.Column("tenant", sa.String(64), nullable=False),
            sa.Column("subject", sa.String(64), nullable=True),
            sa.Column("detection_type", sa.String(64), nullable=False),
            sa.Column("evidence_hash", sa.String(64), nullable=False),
            sa.Column("model_name", sa.String(128), nullable=False),
            sa.Column("model_version", sa.String(64), nullable=False),
            sa.Column("prompt_version", sa.String(64), nullable=False),
            sa.Column("schema_version", sa.String(64), nullable=False),
            sa.Column("knowledge_version", sa.String(64), nullable=False),
            sa.Column("output", JSON_TYPE, nullable=False),
            sa.Column("payload_bytes", sa.Integer(), nullable=False),
            sa.Column("hit_count", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_ai_analysis_cache_tenant_subject", "ai_analysis_cache",
                        ["tenant", "subject", "detection_type"])
        op.create_index("ix_ai_analysis_cache_expires_at", "ai_analysis_cache", ["expires_at"])
        op.create_index("ix_ai_analysis_cache_created_at", "ai_analysis_cache", ["created_at"])
    existing = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("ai_analysis_cache")}
    if "ix_ai_analysis_cache_tenant_evidence" not in existing:
        op.create_index("ix_ai_analysis_cache_tenant_evidence", "ai_analysis_cache",
                        ["tenant", "evidence_hash", "detection_type"])
    if not inspector.has_table("incident_pattern_cases"):
        op.create_table(
            "incident_pattern_cases",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("tenant", sa.String(64), nullable=False),
            sa.Column("incident_id", sa.String(64), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("classification", sa.String(64), nullable=False),
            sa.Column("fingerprint_hash", sa.String(64), nullable=False),
            sa.Column("features", JSON_TYPE, nullable=False),
            sa.Column("guidance", JSON_TYPE, nullable=False),
            sa.Column("analyst_label", sa.String(16), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant", "incident_id", name="uq_incident_pattern_cases_tenant_incident"),
        )
        op.create_index("ix_incident_pattern_cases_lookup", "incident_pattern_cases",
                        ["tenant", "classification", "updated_at"])
        op.create_index("ix_incident_pattern_cases_hash", "incident_pattern_cases", ["tenant", "fingerprint_hash"])


def downgrade():
    op.drop_table("incident_pattern_cases")
    op.drop_table("ai_analysis_cache")
