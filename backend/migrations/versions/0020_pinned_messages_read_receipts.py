"""Add pinned messages and read receipts

Revision ID: 0020
Revises: 0019
Create Date: 2024-12-22

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade():
    # Create pinned_messages table
    op.create_table(
        'pinned_messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('conversation_id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('pinned_by', sa.Integer(), nullable=True),
        sa.Column('pinned_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['pinned_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('conversation_id', 'message_id', name='unique_pinned_message')
    )
    op.create_index(op.f('ix_pinned_messages_id'), 'pinned_messages', ['id'], unique=False)
    op.create_index(op.f('ix_pinned_messages_conversation_id'), 'pinned_messages', ['conversation_id'], unique=False)
    op.create_index(op.f('ix_pinned_messages_message_id'), 'pinned_messages', ['message_id'], unique=False)

    # Create message_read_receipts table
    op.create_table(
        'message_read_receipts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('conversation_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('last_read_message_id', sa.Integer(), nullable=False),
        sa.Column('read_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['last_read_message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('conversation_id', 'user_id', name='unique_read_receipt')
    )
    op.create_index(op.f('ix_message_read_receipts_id'), 'message_read_receipts', ['id'], unique=False)
    op.create_index(op.f('ix_message_read_receipts_conversation_id'), 'message_read_receipts', ['conversation_id'], unique=False)
    op.create_index(op.f('ix_message_read_receipts_user_id'), 'message_read_receipts', ['user_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_message_read_receipts_user_id'), table_name='message_read_receipts')
    op.drop_index(op.f('ix_message_read_receipts_conversation_id'), table_name='message_read_receipts')
    op.drop_index(op.f('ix_message_read_receipts_id'), table_name='message_read_receipts')
    op.drop_table('message_read_receipts')
    
    op.drop_index(op.f('ix_pinned_messages_message_id'), table_name='pinned_messages')
    op.drop_index(op.f('ix_pinned_messages_conversation_id'), table_name='pinned_messages')
    op.drop_index(op.f('ix_pinned_messages_id'), table_name='pinned_messages')
    op.drop_table('pinned_messages')
