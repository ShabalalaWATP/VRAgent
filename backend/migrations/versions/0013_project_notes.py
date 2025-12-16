"""Add project_notes table for general project-level notes.

Revision ID: 0013_project_notes
Revises: 0012_finding_notes
Create Date: 2025-12-12

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0013_project_notes'
down_revision = '0012_finding_notes'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'project_notes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('note_type', sa.String(), nullable=False, server_default='general'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_project_notes_id'), 'project_notes', ['id'], unique=False)
    op.create_index(op.f('ix_project_notes_project_id'), 'project_notes', ['project_id'], unique=False)
    op.create_index(op.f('ix_project_notes_user_id'), 'project_notes', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_project_notes_user_id'), table_name='project_notes')
    op.drop_index(op.f('ix_project_notes_project_id'), table_name='project_notes')
    op.drop_index(op.f('ix_project_notes_id'), table_name='project_notes')
    op.drop_table('project_notes')
