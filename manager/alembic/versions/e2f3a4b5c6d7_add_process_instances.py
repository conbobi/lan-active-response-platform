"""Add process_instances: process history kept across snapshots (Task B)."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e2f3a4b5c6d7"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade():
    if sa.inspect(op.get_bind()).has_table("process_instances"):
        return
    op.create_table(
        "process_instances",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("agent_id", sa.String(64), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("process_start_time", sa.Float(precision=53), nullable=True),
        sa.Column("start_time_source", sa.String(16), nullable=False, server_default="procfs"),
        sa.Column("name", sa.String(128), nullable=False, server_default=""),
        sa.Column("exe", sa.String(1024), nullable=False, server_default=""),
        sa.Column("cmdline", sa.Text(), nullable=False, server_default=""),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("euid", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sources", JSON_TYPE, nullable=False),
        sa.Column("parent_snapshot", JSON_TYPE, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("exited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("exit_signal", sa.Integer(), nullable=True),
    )
    op.create_index("ix_process_instances_agent_pid", "process_instances", ["agent_id", "pid"])
    op.create_index("ix_process_instances_agent_last_seen", "process_instances", ["agent_id", "last_seen"])


def downgrade():
    op.drop_table("process_instances")
