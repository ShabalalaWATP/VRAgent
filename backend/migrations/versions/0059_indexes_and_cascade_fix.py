"""Add missing indexes and fix user deletion cascade for messages.

Revision ID: 0059
Revises: 0058
"""
from alembic import op
import sqlalchemy as sa

revision = '0059'
down_revision = '0058'
branch_labels = None
depends_on = None


def upgrade():
    # Add index on conversations.last_message_at (inbox sort query)
    op.create_index('ix_conversations_last_message_at', 'conversations', ['last_message_at'])

    # Add index on messages.reply_to_id (thread reply counting)
    op.create_index('ix_messages_reply_to_id', 'messages', ['reply_to_id'])

    # Add composite index for the primary message query pattern:
    # WHERE conversation_id = ? AND is_deleted = false ORDER BY created_at DESC
    op.create_index(
        'ix_messages_conv_deleted_created',
        'messages',
        ['conversation_id', 'is_deleted', 'created_at']
    )

    # Change messages.sender_id FK from CASCADE to SET NULL
    # This preserves messages when a user is deleted (shows as "Deleted User")
    op.drop_constraint('messages_sender_id_fkey', 'messages', type_='foreignkey')
    op.alter_column('messages', 'sender_id', nullable=True)
    op.create_foreign_key(
        'messages_sender_id_fkey',
        'messages', 'users',
        ['sender_id'], ['id'],
        ondelete='SET NULL'
    )


def downgrade():
    # Revert FK back to CASCADE
    op.drop_constraint('messages_sender_id_fkey', 'messages', type_='foreignkey')
    op.alter_column('messages', 'sender_id', nullable=False)
    op.create_foreign_key(
        'messages_sender_id_fkey',
        'messages', 'users',
        ['sender_id'], ['id'],
        ondelete='CASCADE'
    )

    # Drop indexes
    op.drop_index('ix_messages_conv_deleted_created', 'messages')
    op.drop_index('ix_messages_reply_to_id', 'messages')
    op.drop_index('ix_conversations_last_message_at', 'conversations')
