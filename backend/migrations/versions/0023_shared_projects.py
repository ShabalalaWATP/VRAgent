"""Add shared projects support

Revision ID: 0023_shared_projects
Revises: 0022_bookmarks_edit
Create Date: 2024-12-23

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '0023_shared_projects'
down_revision = '0022_bookmarks_edit'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_shared field to projects table
    op.add_column('projects', sa.Column('is_shared', sa.String(), nullable=False, server_default='false'))
    
    # Create project_collaborators table
    op.create_table(
        'project_collaborators',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('role', sa.String(), nullable=False, server_default='editor'),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('added_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.UniqueConstraint('project_id', 'user_id', name='uq_project_collaborator'),
    )


def downgrade() -> None:
    op.drop_table('project_collaborators')
    op.drop_column('projects', 'is_shared')
