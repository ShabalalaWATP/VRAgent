"""Add library CVE fields to reverse engineering reports

Revision ID: 0016
Revises: 0015
Create Date: 2024-12-17

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add library CVE columns to reverse_engineering_reports table
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('detected_libraries', sa.JSON(), nullable=True)
    )
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('library_cves', sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    # Remove library CVE columns
    op.drop_column('reverse_engineering_reports', 'library_cves')
    op.drop_column('reverse_engineering_reports', 'detected_libraries')
