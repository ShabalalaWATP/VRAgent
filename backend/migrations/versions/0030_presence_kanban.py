"""Add user presence and kanban models

Revision ID: 0030_presence_kanban
Revises: 0029_add_verification_results
Create Date: 2024-12-25

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON, ARRAY

# revision identifiers, used by Alembic.
revision = '0030_presence_kanban'
down_revision = '0029_add_verification_results'
branch_labels = None
depends_on = None


def upgrade():
    # Create user_presences table
    op.create_table(
        'user_presences',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='online'),
        sa.Column('custom_status', sa.String(length=100), nullable=True),
        sa.Column('status_emoji', sa.String(length=10), nullable=True),
        sa.Column('status_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_active_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    op.create_index('ix_user_presences_user_id', 'user_presences', ['user_id'], unique=True)
    op.create_index('ix_user_presences_status', 'user_presences', ['status'], unique=False)
    
    # Create kanban_boards table
    op.create_table(
        'kanban_boards',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('settings', JSON, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_kanban_boards_project_id', 'kanban_boards', ['project_id'], unique=False)
    
    # Create kanban_columns table
    op.create_table(
        'kanban_columns',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('board_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('color', sa.String(length=20), nullable=True),
        sa.Column('wip_limit', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['board_id'], ['kanban_boards.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_kanban_columns_board_id', 'kanban_columns', ['board_id'], unique=False)
    
    # Create kanban_cards table
    op.create_table(
        'kanban_cards',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('column_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('priority', sa.String(length=20), nullable=True),
        sa.Column('labels', JSON, nullable=True),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('estimated_hours', sa.Float(), nullable=True),
        sa.Column('assignee_ids', JSON, nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('checklist', JSON, nullable=True),
        sa.Column('attachment_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('comment_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['column_id'], ['kanban_columns.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_kanban_cards_column_id', 'kanban_cards', ['column_id'], unique=False)
    op.create_index('ix_kanban_cards_finding_id', 'kanban_cards', ['finding_id'], unique=False)
    
    # Create kanban_card_comments table
    op.create_table(
        'kanban_card_comments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('card_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.ForeignKeyConstraint(['card_id'], ['kanban_cards.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_kanban_card_comments_card_id', 'kanban_card_comments', ['card_id'], unique=False)


def downgrade():
    op.drop_index('ix_kanban_card_comments_card_id', table_name='kanban_card_comments')
    op.drop_table('kanban_card_comments')
    
    op.drop_index('ix_kanban_cards_finding_id', table_name='kanban_cards')
    op.drop_index('ix_kanban_cards_column_id', table_name='kanban_cards')
    op.drop_table('kanban_cards')
    
    op.drop_index('ix_kanban_columns_board_id', table_name='kanban_columns')
    op.drop_table('kanban_columns')
    
    op.drop_index('ix_kanban_boards_project_id', table_name='kanban_boards')
    op.drop_table('kanban_boards')
    
    op.drop_index('ix_user_presences_status', table_name='user_presences')
    op.drop_index('ix_user_presences_user_id', table_name='user_presences')
    op.drop_table('user_presences')
