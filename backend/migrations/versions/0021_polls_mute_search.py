"""Add polls tables and muted_until field

Revision ID: 0021_polls_mute_search
Revises: 0020
Create Date: 2024-12-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0021_polls_mute_search'
down_revision = '0020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add muted_until to conversation_participants
    op.add_column(
        'conversation_participants',
        sa.Column('muted_until', sa.DateTime(timezone=True), nullable=True)
    )
    
    # Create polls table
    op.create_table(
        'polls',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('conversation_id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('question', sa.Text(), nullable=False),
        sa.Column('poll_type', sa.String(), nullable=False, server_default='single'),
        sa.Column('is_anonymous', sa.String(), nullable=False, server_default='false'),
        sa.Column('allow_add_options', sa.String(), nullable=False, server_default='false'),
        sa.Column('closes_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_closed', sa.String(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_polls_id'), 'polls', ['id'], unique=False)
    op.create_index(op.f('ix_polls_conversation_id'), 'polls', ['conversation_id'], unique=False)
    op.create_index(op.f('ix_polls_message_id'), 'polls', ['message_id'], unique=False)
    
    # Create poll_options table
    op.create_table(
        'poll_options',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('poll_id', sa.Integer(), nullable=False),
        sa.Column('text', sa.String(500), nullable=False),
        sa.Column('added_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['poll_id'], ['polls.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_poll_options_id'), 'poll_options', ['id'], unique=False)
    op.create_index(op.f('ix_poll_options_poll_id'), 'poll_options', ['poll_id'], unique=False)
    
    # Create poll_votes table
    op.create_table(
        'poll_votes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('option_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('voted_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['option_id'], ['poll_options.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('option_id', 'user_id', name='unique_poll_vote')
    )
    op.create_index(op.f('ix_poll_votes_id'), 'poll_votes', ['id'], unique=False)
    op.create_index(op.f('ix_poll_votes_option_id'), 'poll_votes', ['option_id'], unique=False)
    
    # Create full-text search index on messages.content for better search performance
    # PostgreSQL specific
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_messages_content_search 
        ON messages USING gin(to_tsvector('english', content))
    """)


def downgrade() -> None:
    # Drop full-text search index
    op.execute("DROP INDEX IF EXISTS ix_messages_content_search")
    
    # Drop poll tables
    op.drop_index(op.f('ix_poll_votes_option_id'), table_name='poll_votes')
    op.drop_index(op.f('ix_poll_votes_id'), table_name='poll_votes')
    op.drop_table('poll_votes')
    
    op.drop_index(op.f('ix_poll_options_poll_id'), table_name='poll_options')
    op.drop_index(op.f('ix_poll_options_id'), table_name='poll_options')
    op.drop_table('poll_options')
    
    op.drop_index(op.f('ix_polls_message_id'), table_name='polls')
    op.drop_index(op.f('ix_polls_conversation_id'), table_name='polls')
    op.drop_index(op.f('ix_polls_id'), table_name='polls')
    op.drop_table('polls')
    
    # Remove muted_until column
    op.drop_column('conversation_participants', 'muted_until')
