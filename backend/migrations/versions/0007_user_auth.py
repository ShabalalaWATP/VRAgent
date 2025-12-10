"""add user authentication fields

Revision ID: 0007
Revises: 0006
Create Date: 2025-01-18 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0007_user_auth'
down_revision = '0006_fuzzing_sessions'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to users table
    # First, add nullable columns
    op.add_column('users', sa.Column('username', sa.String(), nullable=True))
    op.add_column('users', sa.Column('password_hash', sa.String(), nullable=True))
    op.add_column('users', sa.Column('role', sa.String(), nullable=True))
    op.add_column('users', sa.Column('status', sa.String(), nullable=True))
    op.add_column('users', sa.Column('last_login', sa.DateTime(timezone=True), nullable=True))
    
    # Set default values for existing users
    op.execute("""
        UPDATE users 
        SET 
            username = COALESCE(SPLIT_PART(email, '@', 1), 'user_' || id::text),
            password_hash = '',
            role = 'user',
            status = 'approved'
        WHERE username IS NULL
    """)
    
    # Make columns non-nullable where required
    op.alter_column('users', 'username', nullable=False)
    op.alter_column('users', 'password_hash', nullable=False)
    op.alter_column('users', 'role', nullable=False)
    op.alter_column('users', 'status', nullable=False)
    op.alter_column('users', 'email', nullable=False)
    
    # Add unique constraint on username
    op.create_unique_constraint('uq_users_username', 'users', ['username'])
    
    # Add index on username for faster lookups
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)


def downgrade() -> None:
    # Remove indexes
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    
    # Remove unique constraint
    op.drop_constraint('uq_users_username', 'users', type_='unique')
    
    # Make email nullable again
    op.alter_column('users', 'email', nullable=True)
    
    # Remove new columns
    op.drop_column('users', 'last_login')
    op.drop_column('users', 'status')
    op.drop_column('users', 'role')
    op.drop_column('users', 'password_hash')
    op.drop_column('users', 'username')
