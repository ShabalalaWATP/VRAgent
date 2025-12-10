"""Add network_analysis_reports table

Revision ID: 0004
Revises: 0003
Create Date: 2025-01-15 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'network_analysis_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('analysis_type', sa.String(50), nullable=False),  # 'pcap' or 'nmap'
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('filename', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('risk_level', sa.String(20), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('summary_data', JSONB(), nullable=True),
        sa.Column('findings_data', JSONB(), nullable=True),
        sa.Column('ai_report', JSONB(), nullable=True),
        sa.Column('last_exported_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('export_formats', JSONB(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create index on analysis_type for filtering
    op.create_index(
        'ix_network_analysis_reports_type',
        'network_analysis_reports',
        ['analysis_type']
    )
    
    # Create index on created_at for sorting
    op.create_index(
        'ix_network_analysis_reports_created_at',
        'network_analysis_reports',
        ['created_at']
    )


def downgrade() -> None:
    op.drop_index('ix_network_analysis_reports_created_at', table_name='network_analysis_reports')
    op.drop_index('ix_network_analysis_reports_type', table_name='network_analysis_reports')
    op.drop_table('network_analysis_reports')
