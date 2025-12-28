"""Add message_bookmarks and message_edit_history tables

Revision ID: 0022_bookmarks_edit
Revises: 0021_polls_mute_search
Create Date: 2024-12-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0022_bookmarks_edit'
down_revision = '0021_polls_mute_search'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create message_bookmarks table
    op.create_table(
        'message_bookmarks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'message_id', name='unique_message_bookmark')
    )
    op.create_index(op.f('ix_message_bookmarks_id'), 'message_bookmarks', ['id'], unique=False)
    op.create_index(op.f('ix_message_bookmarks_user_id'), 'message_bookmarks', ['user_id'], unique=False)
    op.create_index(op.f('ix_message_bookmarks_message_id'), 'message_bookmarks', ['message_id'], unique=False)
    
    # Create message_edit_history table
    op.create_table(
        'message_edit_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('previous_content', sa.Text(), nullable=False),
        sa.Column('edited_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('edit_number', sa.Integer(), nullable=False, server_default='1'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_message_edit_history_id'), 'message_edit_history', ['id'], unique=False)
    op.create_index(op.f('ix_message_edit_history_message_id'), 'message_edit_history', ['message_id'], unique=False)


def downgrade() -> None:
    # Drop message_edit_history table
    op.drop_index(op.f('ix_message_edit_history_message_id'), table_name='message_edit_history')
    op.drop_index(op.f('ix_message_edit_history_id'), table_name='message_edit_history')
    op.drop_table('message_edit_history')
    
    # Drop message_bookmarks table
    op.drop_index(op.f('ix_message_bookmarks_message_id'), table_name='message_bookmarks')
    op.drop_index(op.f('ix_message_bookmarks_user_id'), table_name='message_bookmarks')
    op.drop_index(op.f('ix_message_bookmarks_id'), table_name='message_bookmarks')
    op.drop_table('message_bookmarks')
