"""Add rule_monitor_hits for rules running in monitoring mode."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d1e2f3a4b5c6"
down_revision = "c8d9e0f1a2b3"
branch_labels = None
depends_on = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade():
    if sa.inspect(op.get_bind()).has_table("rule_monitor_hits"):
        return
    op.create_table(
        "rule_monitor_hits",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("rule_candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("evidence_id", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("process", JSON_TYPE, nullable=True),
        sa.UniqueConstraint("rule_id", "evidence_id", name="uq_rule_monitor_hit_evidence"),
    )
    op.create_index("ix_rule_monitor_hits_rule_id", "rule_monitor_hits", ["rule_id"])
    op.create_index("ix_rule_monitor_hits_observed_at", "rule_monitor_hits", ["observed_at"])


def downgrade():
    op.drop_table("rule_monitor_hits")
