"""Add SOC user accounts, agent scopes, refresh sessions, and auth audit logs."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c8d9e0f1a2b3"
down_revision = "b7e4c2a91d35"
branch_labels = None
depends_on = None

JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("soc_users"):
        op.create_table(
            "soc_users",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("username", sa.String(64), nullable=False),
            sa.Column("password_hash", sa.String(512), nullable=False),
            sa.Column("role", sa.String(16), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("username", name="uq_soc_users_username"),
        )
        op.create_index("ix_soc_users_username", "soc_users", ["username"])

    if not inspector.has_table("soc_user_agent_scopes"):
        op.create_table(
            "soc_user_agent_scopes",
            sa.Column("user_id", sa.String(64), sa.ForeignKey("soc_users.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("agent_id", sa.String(64), primary_key=True),
        )

    if not inspector.has_table("soc_refresh_sessions"):
        op.create_table(
            "soc_refresh_sessions",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("user_id", sa.String(64), sa.ForeignKey("soc_users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("refresh_token_hash", sa.String(64), nullable=False),
            sa.Column("token_family_id", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("replaced_by_id", sa.String(64), nullable=True),
            sa.Column("device_metadata", JSON_TYPE, nullable=False),
            sa.Column("reuse_detected_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("refresh_token_hash", name="uq_soc_refresh_sessions_token_hash"),
        )
        op.create_index("ix_soc_refresh_sessions_user_id", "soc_refresh_sessions", ["user_id"])
        op.create_index("ix_soc_refresh_sessions_token_family_id", "soc_refresh_sessions", ["token_family_id"])
        op.create_index("ix_soc_refresh_sessions_expires_at", "soc_refresh_sessions", ["expires_at"])
        op.create_index("ix_soc_refresh_sessions_user_active", "soc_refresh_sessions", ["user_id", "revoked_at"])

    if not inspector.has_table("soc_auth_audit_logs"):
        op.create_table(
            "soc_auth_audit_logs",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("user_id", sa.String(64), nullable=True),
            sa.Column("username", sa.String(64), nullable=True),
            sa.Column("event", sa.String(48), nullable=False),
            sa.Column("ip_address", sa.String(64), nullable=True),
            sa.Column("detail", JSON_TYPE, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_soc_auth_audit_logs_user_id", "soc_auth_audit_logs", ["user_id"])
        op.create_index("ix_soc_auth_audit_logs_username", "soc_auth_audit_logs", ["username"])
        op.create_index("ix_soc_auth_audit_logs_event", "soc_auth_audit_logs", ["event"])
        op.create_index("ix_soc_auth_audit_logs_created_at", "soc_auth_audit_logs", ["created_at"])


def downgrade():
    op.drop_table("soc_auth_audit_logs")
    op.drop_table("soc_refresh_sessions")
    op.drop_table("soc_user_agent_scopes")
    op.drop_table("soc_users")

