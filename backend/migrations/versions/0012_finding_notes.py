"""Add finding_notes table for user notes on findings.

Revision ID: 0012_finding_notes
Revises: 0011_network_project
Create Date: 2025-12-12

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0012_finding_notes'
down_revision = '0011_network_project'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'finding_notes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('note_type', sa.String(), nullable=False, server_default='comment'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_finding_notes_id'), 'finding_notes', ['id'], unique=False)
    op.create_index(op.f('ix_finding_notes_finding_id'), 'finding_notes', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_notes_user_id'), 'finding_notes', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_finding_notes_user_id'), table_name='finding_notes')
    op.drop_index(op.f('ix_finding_notes_finding_id'), table_name='finding_notes')
    op.drop_index(op.f('ix_finding_notes_id'), table_name='finding_notes')
    op.drop_table('finding_notes')
