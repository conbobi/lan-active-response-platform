"""Add the current per-Agent network snapshot."""

import sqlalchemy as sa
from alembic import op

revision = "31cc534dcc0f"
down_revision = "70d809d543c1"
branch_labels = None
depends_on = None


def upgrade():
    # Manager also applies these additive changes during normal startup.
    inspector = sa.inspect(op.get_bind())
    if all(column["name"] != "process_start_time" for column in inspector.get_columns("process_info")):
        op.add_column("process_info", sa.Column("process_start_time", sa.Float(53), nullable=True))
    if inspector.has_table("network_snapshots"):
        return
    op.create_table(
        "network_snapshots",
        sa.Column("agent_id", sa.String(64), sa.ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_network_snapshots_received_at", "network_snapshots", ["received_at"])


def downgrade():
    op.drop_table("network_snapshots")
    op.drop_column("process_info", "process_start_time")
