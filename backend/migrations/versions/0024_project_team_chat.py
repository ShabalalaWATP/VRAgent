"""Add project_id to conversations for team chat

Revision ID: 0024_project_team_chat
Revises: 0023_shared_projects
Create Date: 2024-12-23

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '0024_project_team_chat'
down_revision = '0023_shared_projects'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add project_id field to conversations table
    op.add_column('conversations', sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=True, index=True))
    op.create_index('ix_conversations_project_id', 'conversations', ['project_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_conversations_project_id', table_name='conversations')
    op.drop_column('conversations', 'project_id')
