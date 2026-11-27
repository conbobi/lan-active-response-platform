"""Persist grounded assistant turns across dashboard reloads."""
from alembic import op
from app.models.rule_conversation import RuleConversation

revision = "c72d6e1f037a"
down_revision = "b5c6d7e8f9a0"
branch_labels = depends_on = None


def upgrade():
    RuleConversation.__table__.create(bind=op.get_bind(), checkfirst=True)


def downgrade():
    op.drop_table("rule_conversations")
