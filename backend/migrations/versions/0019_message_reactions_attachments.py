"""Add message reactions and reply support

Revision ID: 0019
Revises: 0018_group_chats_notes
Create Date: 2024-12-22

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '0019'
down_revision = '0018_group_chats_notes'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create message_reactions table
    op.create_table(
        'message_reactions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('emoji', sa.String(32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('message_id', 'user_id', 'emoji', name='unique_message_reaction')
    )
    op.create_index('ix_message_reactions_id', 'message_reactions', ['id'])
    op.create_index('ix_message_reactions_message_id', 'message_reactions', ['message_id'])
    op.create_index('ix_message_reactions_user_id', 'message_reactions', ['user_id'])
    
    # Add reply_to_id to messages table
    op.add_column('messages', sa.Column('reply_to_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_messages_reply_to_id',
        'messages', 'messages',
        ['reply_to_id'], ['id'],
        ondelete='SET NULL'
    )


def downgrade() -> None:
    # Remove reply_to_id from messages
    op.drop_constraint('fk_messages_reply_to_id', 'messages', type_='foreignkey')
    op.drop_column('messages', 'reply_to_id')
    
    # Drop message_reactions table
    op.drop_index('ix_message_reactions_user_id', 'message_reactions')
    op.drop_index('ix_message_reactions_message_id', 'message_reactions')
    op.drop_index('ix_message_reactions_id', 'message_reactions')
    op.drop_table('message_reactions')
