"""Add report_data column for DNS and other report types

Revision ID: 0005
Revises: 0004
Create Date: 2025-01-20 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add report_data column for flexible data storage (used by DNS, etc.)
    op.add_column(
        'network_analysis_reports',
        sa.Column('report_data', JSONB(), nullable=True)
    )
    
    # Add report_type column as an alias/alternative categorization
    # This allows more flexibility (dns, pcap, nmap, etc.)
    op.add_column(
        'network_analysis_reports',
        sa.Column('report_type', sa.String(50), nullable=True)
    )
    
    # Create index on report_type for filtering
    op.create_index(
        'ix_network_analysis_reports_report_type',
        'network_analysis_reports',
        ['report_type']
    )
    
    # Backfill report_type from analysis_type for existing records
    op.execute(
        "UPDATE network_analysis_reports SET report_type = analysis_type WHERE report_type IS NULL"
    )


def downgrade() -> None:
    op.drop_index('ix_network_analysis_reports_report_type', table_name='network_analysis_reports')
    op.drop_column('network_analysis_reports', 'report_type')
    op.drop_column('network_analysis_reports', 'report_data')
