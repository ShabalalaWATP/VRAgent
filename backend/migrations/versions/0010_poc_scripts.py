"""Add POC scripts and attack complexity to exploit scenarios

Revision ID: 0010
Revises: 0009_scan_run_options
Create Date: 2025-01-15
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0010'
down_revision = '0009_scan_run_options'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to exploit_scenarios table
    op.add_column('exploit_scenarios', sa.Column('poc_scripts', sa.JSON(), nullable=True))
    op.add_column('exploit_scenarios', sa.Column('attack_complexity', sa.String(), nullable=True))
    op.add_column('exploit_scenarios', sa.Column('exploit_maturity', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('exploit_scenarios', 'poc_scripts')
    op.drop_column('exploit_scenarios', 'attack_complexity')
    op.drop_column('exploit_scenarios', 'exploit_maturity')
