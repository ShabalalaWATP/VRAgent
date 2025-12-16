"""Add options column to scan_runs table

Revision ID: 0009_scan_run_options
Revises: 0008_user_names
Create Date: 2024-12-11

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0009_scan_run_options'
down_revision = '0008_user_names'
branch_labels = None
depends_on = None


def upgrade():
    # Add options column to scan_runs table for storing scan configuration
    # like include_agentic flag
    op.add_column('scan_runs', sa.Column('options', sa.JSON(), nullable=True))


def downgrade():
    # Remove options column
    op.drop_column('scan_runs', 'options')
