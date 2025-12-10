"""Add first_name and last_name to users table

Revision ID: 0008_user_names
Revises: 0007_user_auth
Create Date: 2024-12-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0008_user_names'
down_revision = '0007_user_auth'
branch_labels = None
depends_on = None


def upgrade():
    # Add first_name and last_name columns to users table
    op.add_column('users', sa.Column('first_name', sa.String(), nullable=True))
    op.add_column('users', sa.Column('last_name', sa.String(), nullable=True))


def downgrade():
    # Remove first_name and last_name columns
    op.drop_column('users', 'last_name')
    op.drop_column('users', 'first_name')
