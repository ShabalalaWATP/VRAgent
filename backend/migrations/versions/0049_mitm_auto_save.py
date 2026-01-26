"""Add auto-save support to MITM reports

Revision ID: 0049_mitm_auto_save
Revises: 0048_mitm_agentic_data
Create Date: 2026-01-23

Allows MITM analysis reports to be auto-saved without requiring a project.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = '0049_mitm_auto_save'
down_revision = '0048_mitm_agentic_data'
branch_labels = None
depends_on = None


def upgrade():
    # Make project_id nullable for auto-saved reports
    op.alter_column('mitm_analysis_reports', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=True)

    # Add auto_saved flag
    op.add_column('mitm_analysis_reports',
                  sa.Column('auto_saved', sa.Boolean(), nullable=True, default=False))

    # Add target info for display in saved scans list
    op.add_column('mitm_analysis_reports',
                  sa.Column('target_host', sa.String(255), nullable=True))
    op.add_column('mitm_analysis_reports',
                  sa.Column('target_port', sa.Integer(), nullable=True))

    # Set default for existing records
    op.execute("UPDATE mitm_analysis_reports SET auto_saved = false WHERE auto_saved IS NULL")


def downgrade():
    # Remove added columns
    op.drop_column('mitm_analysis_reports', 'target_port')
    op.drop_column('mitm_analysis_reports', 'target_host')
    op.drop_column('mitm_analysis_reports', 'auto_saved')

    # Make project_id required again (may fail if null values exist)
    op.alter_column('mitm_analysis_reports', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=False)
