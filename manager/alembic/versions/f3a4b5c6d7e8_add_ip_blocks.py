"""Add ip_blocks, ip_unblocks, ip_block_events (host IP block lifecycle)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f3a4b5c6d7e8"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None

J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("ip_blocks"):
        op.create_table(
            "ip_blocks",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("agent_id", sa.String(64), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.String(64), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
            sa.Column("target_ip", sa.String(64), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("evidence", J, nullable=True),
            sa.Column("firewall_backend", sa.String(16), nullable=False, server_default="nftables"),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("effective_state", sa.String(24), nullable=False),
            sa.Column("requested_by", sa.String(128), nullable=False),
            sa.Column("approved_by", sa.String(128), nullable=True),
            sa.Column("command_id", sa.String(64), nullable=True),
            sa.Column("firewall_rules", J, nullable=True),
            sa.Column("receipt", J, nullable=True),
            sa.Column("last_verification", J, nullable=True),
            sa.Column("error", sa.String(512), nullable=True),
            *[sa.Column(name, TS, nullable=name not in ("created_at", "updated_at")) for name in (
                "created_at", "updated_at", "approved_at", "dispatched_at", "executed_at", "verified_at",
                "traffic_verified_at", "expires_at")],
        )
        op.create_index("ix_ip_blocks_agent_ip", "ip_blocks", ["agent_id", "target_ip"])
        op.create_index("ix_ip_blocks_agent_id", "ip_blocks", ["agent_id"])
        op.create_index("ix_ip_blocks_status", "ip_blocks", ["status"])
        op.create_index("ix_ip_blocks_effective_state", "ip_blocks", ["effective_state"])
    if not inspector.has_table("ip_unblocks"):
        op.create_table(
            "ip_unblocks",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("block_id", sa.String(32), sa.ForeignKey("ip_blocks.id", ondelete="CASCADE"), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=False),
            sa.Column("target_ip", sa.String(64), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("access_state", sa.String(24), nullable=False),
            sa.Column("requested_by", sa.String(128), nullable=False),
            sa.Column("approved_by", sa.String(128), nullable=True),
            sa.Column("command_id", sa.String(64), nullable=True),
            sa.Column("firewall_removal_result", J, nullable=True),
            sa.Column("connectivity_verification", J, nullable=True),
            sa.Column("error", sa.String(512), nullable=True),
            *[sa.Column(name, TS, nullable=name != "created_at") for name in (
                "created_at", "approved_at", "dispatched_at", "executed_at", "verified_at")],
        )
        op.create_index("ix_ip_unblocks_block_id", "ip_unblocks", ["block_id"])
    if not inspector.has_table("ip_block_events"):
        op.create_table(
            "ip_block_events",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("block_id", sa.String(32), sa.ForeignKey("ip_blocks.id", ondelete="CASCADE"), nullable=False),
            sa.Column("unblock_id", sa.String(32), nullable=True),
            sa.Column("event", sa.String(48), nullable=False),
            sa.Column("actor", sa.String(128), nullable=False),
            sa.Column("detail", J, nullable=True),
            sa.Column("at", TS, nullable=False),
        )
        op.create_index("ix_ip_block_events_block_id", "ip_block_events", ["block_id"])


def downgrade():
    op.drop_table("ip_block_events")
    op.drop_table("ip_unblocks")
    op.drop_table("ip_blocks")
