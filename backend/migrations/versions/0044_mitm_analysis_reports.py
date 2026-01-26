"""Add MITM Analysis Reports table

Revision ID: 0044_mitm_analysis
Revises: 0043_malware_analysis
Create Date: 2026-01-22

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0044_mitm_analysis'
down_revision = '0043_malware_analysis'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'mitm_analysis_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('proxy_id', sa.String(64), nullable=False),
        sa.Column('session_id', sa.String(128), nullable=True),
        sa.Column('title', sa.String(500), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('traffic_analyzed', sa.Integer(), default=0),
        sa.Column('rules_active', sa.Integer(), default=0),
        sa.Column('findings_count', sa.Integer(), default=0),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('risk_level', sa.String(20), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('analysis_passes', sa.Integer(), default=3),
        sa.Column('pass1_findings', sa.Integer(), default=0),
        sa.Column('pass2_ai_findings', sa.Integer(), default=0),
        sa.Column('after_dedup', sa.Integer(), default=0),
        sa.Column('false_positives_removed', sa.Integer(), default=0),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('attack_paths', sa.JSON(), nullable=True),
        sa.Column('recommendations', sa.JSON(), nullable=True),
        sa.Column('exploit_references', sa.JSON(), nullable=True),
        sa.Column('cve_references', sa.JSON(), nullable=True),
        sa.Column('ai_exploitation_writeup', sa.Text(), nullable=True),
        sa.Column('ai_remediation_writeup', sa.Text(), nullable=True),
        sa.Column('traffic_snapshot', sa.JSON(), nullable=True),
        sa.Column('pdf_exported', sa.Boolean(), default=False),
        sa.Column('docx_exported', sa.Boolean(), default=False),
        sa.Column('markdown_exported', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mitm_analysis_reports_id'), 'mitm_analysis_reports', ['id'], unique=False)
    op.create_index(op.f('ix_mitm_analysis_reports_project_id'), 'mitm_analysis_reports', ['project_id'], unique=False)
    op.create_index(op.f('ix_mitm_analysis_reports_user_id'), 'mitm_analysis_reports', ['user_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_mitm_analysis_reports_user_id'), table_name='mitm_analysis_reports')
    op.drop_index(op.f('ix_mitm_analysis_reports_project_id'), table_name='mitm_analysis_reports')
    op.drop_index(op.f('ix_mitm_analysis_reports_id'), table_name='mitm_analysis_reports')
    op.drop_table('mitm_analysis_reports')
