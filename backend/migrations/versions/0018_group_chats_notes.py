"""Add group chat support and user notes

Revision ID: 0018_group_chats_notes
Revises: 0017_social_features
Create Date: 2024-12-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0018_group_chats_notes'
down_revision = '0017_social_features'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to conversations table for group chat support
    op.add_column('conversations', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('conversations', sa.Column('avatar_url', sa.String(), nullable=True))
    op.add_column('conversations', sa.Column('created_by', sa.Integer(), nullable=True))
    
    # Add foreign key for created_by
    op.create_foreign_key(
        'fk_conversations_created_by',
        'conversations', 'users',
        ['created_by'], ['id'],
        ondelete='SET NULL'
    )
    
    # Update conversation_participants table - replace is_admin with role-based system
    # First add new columns
    op.add_column('conversation_participants', sa.Column('role', sa.String(), nullable=False, server_default='member'))
    op.add_column('conversation_participants', sa.Column('added_by', sa.Integer(), nullable=True))
    op.add_column('conversation_participants', sa.Column('nickname', sa.String(), nullable=True))
    op.add_column('conversation_participants', sa.Column('is_muted', sa.String(), nullable=False, server_default='false'))
    
    # Add foreign key for added_by
    op.create_foreign_key(
        'fk_conversation_participants_added_by',
        'conversation_participants', 'users',
        ['added_by'], ['id'],
        ondelete='SET NULL'
    )
    
    # Migrate is_admin data to role column
    op.execute("UPDATE conversation_participants SET role = 'admin' WHERE is_admin = 'true'")
    
    # Drop the old is_admin column
    op.drop_column('conversation_participants', 'is_admin')
    
    # Create user_notes table for personal notes about other users
    op.create_table(
        'user_notes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('subject_id', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subject_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'subject_id', name='unique_user_note')
    )
    op.create_index('ix_user_notes_id', 'user_notes', ['id'])
    op.create_index('ix_user_notes_owner_id', 'user_notes', ['owner_id'])
    op.create_index('ix_user_notes_subject_id', 'user_notes', ['subject_id'])


def downgrade() -> None:
    # Drop user_notes table
    op.drop_index('ix_user_notes_subject_id', table_name='user_notes')
    op.drop_index('ix_user_notes_owner_id', table_name='user_notes')
    op.drop_index('ix_user_notes_id', table_name='user_notes')
    op.drop_table('user_notes')
    
    # Restore is_admin column
    op.add_column('conversation_participants', sa.Column('is_admin', sa.String(), nullable=False, server_default='false'))
    
    # Migrate role data back to is_admin
    op.execute("UPDATE conversation_participants SET is_admin = 'true' WHERE role IN ('admin', 'owner')")
    
    # Drop new columns from conversation_participants
    op.drop_constraint('fk_conversation_participants_added_by', 'conversation_participants', type_='foreignkey')
    op.drop_column('conversation_participants', 'is_muted')
    op.drop_column('conversation_participants', 'nickname')
    op.drop_column('conversation_participants', 'added_by')
    op.drop_column('conversation_participants', 'role')
    
    # Drop new columns from conversations
    op.drop_constraint('fk_conversations_created_by', 'conversations', type_='foreignkey')
    op.drop_column('conversations', 'created_by')
    op.drop_column('conversations', 'avatar_url')
    op.drop_column('conversations', 'description')
