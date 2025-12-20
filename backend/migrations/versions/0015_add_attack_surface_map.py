"""Add ai_attack_surface_map to reverse engineering reports

Revision ID: 0015
Revises: 0014_re_report_jadx
Create Date: 2024-12-17

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0015'
down_revision = '0014_re_report_jadx'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add ai_attack_surface_map column to reverse_engineering_reports table
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('ai_attack_surface_map', sa.Text(), nullable=True)
    )


def downgrade() -> None:
    # Remove ai_attack_surface_map column
    op.drop_column('reverse_engineering_reports', 'ai_attack_surface_map')
