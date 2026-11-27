"""Add containment_actions and containment_events."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b5c6d7e8f9a0"
down_revision = "a4b5c6d7e8f9"
branch_labels = None
depends_on = None

J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("containment_actions"):
        op.create_table(
            "containment_actions",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("incident_id", sa.String(64), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("agent_id", sa.String(64), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(40), nullable=False),
            sa.Column("target", J, nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("requires_approval", sa.Boolean(), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("effect", sa.String(32), nullable=False),
            sa.Column("parent_action_id", sa.String(32), nullable=True),
            sa.Column("requested_by", sa.String(128), nullable=False),
            sa.Column("approved_by", sa.String(128), nullable=True),
            sa.Column("command_id", sa.String(64), nullable=True),
            sa.Column("receipt", J, nullable=True),
            sa.Column("verification", J, nullable=True),
            sa.Column("error", sa.String(512), nullable=True),
            *[sa.Column(n, TS, nullable=n != "created_at") for n in (
                "created_at", "approved_at", "dispatched_at", "executed_at", "verified_at")],
        )
        op.create_index("ix_containment_actions_incident", "containment_actions", ["incident_id", "created_at"])
        op.create_index("ix_containment_actions_agent_id", "containment_actions", ["agent_id"])
    if not inspector.has_table("containment_events"):
        op.create_table(
            "containment_events",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("action_id", sa.String(32), sa.ForeignKey("containment_actions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("event", sa.String(48), nullable=False),
            sa.Column("actor", sa.String(128), nullable=False),
            sa.Column("detail", J, nullable=True),
            sa.Column("at", TS, nullable=False),
        )
        op.create_index("ix_containment_events_action_id", "containment_events", ["action_id"])


def downgrade():
    op.drop_table("containment_events")
    op.drop_table("containment_actions")
