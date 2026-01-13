"""Add agentic_scan_reports table

Revision ID: 0032_agentic_scan_reports
Revises: 0031_finding_is_duplicate
Create Date: 2026-01-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0032_agentic_scan_reports'
down_revision = '0031_finding_is_duplicate'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'agentic_scan_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.String(length=100), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('project_path', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('total_chunks', sa.Integer(), nullable=True),
        sa.Column('analyzed_chunks', sa.Integer(), nullable=True),
        sa.Column('entry_points_found', sa.Integer(), nullable=True),
        sa.Column('flows_traced', sa.Integer(), nullable=True),
        sa.Column('findings_critical', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_high', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_medium', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_low', sa.Integer(), server_default='0', nullable=True),
        sa.Column('findings_info', sa.Integer(), server_default='0', nullable=True),
        sa.Column('executive_summary', sa.Text(), nullable=True),
        sa.Column('vulnerabilities', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('entry_points', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('traced_flows', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('statistics', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_agentic_scan_reports_id', 'agentic_scan_reports', ['id'], unique=False)
    op.create_index('ix_agentic_scan_reports_project_id', 'agentic_scan_reports', ['project_id'], unique=False)
    op.create_index('ix_agentic_scan_reports_scan_id', 'agentic_scan_reports', ['scan_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_agentic_scan_reports_scan_id', table_name='agentic_scan_reports')
    op.drop_index('ix_agentic_scan_reports_project_id', table_name='agentic_scan_reports')
    op.drop_index('ix_agentic_scan_reports_id', table_name='agentic_scan_reports')
    op.drop_table('agentic_scan_reports')
