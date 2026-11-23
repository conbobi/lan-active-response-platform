"""Persist incident-scoped detection evidence."""

from alembic import op
import sqlalchemy as sa

revision = "2cf5cedde42e"
down_revision = "31cc534dcc0f"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    for table, name in (("incidents", "detection_evidence"), ("flows", "socket_evidence")):
        if not any(column["name"] == name for column in inspector.get_columns(table)):
            op.add_column(table, sa.Column(name, sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("flows", "socket_evidence")
    op.drop_column("incidents", "detection_evidence")
