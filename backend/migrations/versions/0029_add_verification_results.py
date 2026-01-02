"""Add verification_results column to reverse_engineering_reports

Revision ID: 0029_add_verification_results
Revises: 0028_manifest_obf
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0029_add_verification_results'
down_revision = '0028_manifest_obf'
branch_labels = None
depends_on = None


def upgrade():
    # Add verification_results column to reverse_engineering_reports table
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('verification_results', sa.JSON(), nullable=True)
    )


def downgrade():
    # Remove verification_results column
    op.drop_column('reverse_engineering_reports', 'verification_results')
