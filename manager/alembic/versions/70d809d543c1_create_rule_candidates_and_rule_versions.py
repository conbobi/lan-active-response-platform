"""create_rule_candidates_and_rule_versions

Revision ID: 70d809d543c1
Revises: 
Create Date: 2026-11-15 06:19:07.770455

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '70d809d543c1'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'rule_candidates',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('rule_yaml', sa.Text(), nullable=False),
        sa.Column('rule_name', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=32), server_default='ai_harvest', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='pending', nullable=False),
        sa.Column('validation_result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('fpr', sa.Float(), nullable=True),
        sa.Column('precision', sa.Float(), nullable=True),
        sa.Column('recall', sa.Float(), nullable=True),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('severity', sa.String(length=16), server_default='medium', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('validated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(length=128), nullable=True),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('model_generated', sa.String(length=64), nullable=True),
        sa.Column('harvest_prompt', sa.Text(), nullable=True),
        sa.Column('false_positive_samples', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_rule_candidates_rule_name'), 'rule_candidates', ['rule_name'], unique=False)
    op.create_index(op.f('ix_rule_candidates_source'), 'rule_candidates', ['source'], unique=False)
    op.create_index(op.f('ix_rule_candidates_status'), 'rule_candidates', ['status'], unique=False)
    op.create_index(op.f('ix_rule_candidates_severity'), 'rule_candidates', ['severity'], unique=False)

    op.create_table(
        'rule_versions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_candidate_id', sa.Uuid(), nullable=False),
        sa.Column('version_number', sa.Integer(), server_default='1', nullable=False),
        sa.Column('yaml_content', sa.Text(), nullable=False),
        sa.Column('change_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(['rule_candidate_id'], ['rule_candidates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_rule_versions_rule_candidate_id'), 'rule_versions', ['rule_candidate_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_rule_versions_rule_candidate_id'), table_name='rule_versions')
    op.drop_table('rule_versions')
    op.drop_index(op.f('ix_rule_candidates_severity'), table_name='rule_candidates')
    op.drop_index(op.f('ix_rule_candidates_status'), table_name='rule_candidates')
    op.drop_index(op.f('ix_rule_candidates_source'), table_name='rule_candidates')
    op.drop_index(op.f('ix_rule_candidates_rule_name'), table_name='rule_candidates')
    op.drop_table('rule_candidates')
