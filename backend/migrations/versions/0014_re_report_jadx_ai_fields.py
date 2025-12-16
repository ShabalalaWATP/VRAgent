"""Add JADX and AI report fields to ReverseEngineeringReport

Revision ID: 0014_re_report_jadx
Revises: 0013_project_notes
Create Date: 2025-01-14

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0014_re_report_jadx'
down_revision: Union[str, None] = '0013_project_notes'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add JADX Full Scan columns
    op.add_column('reverse_engineering_reports', 
        sa.Column('jadx_total_classes', sa.Integer(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('jadx_total_files', sa.Integer(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('jadx_data', sa.JSON(), nullable=True))
    
    # Add AI-Generated Report columns
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_functionality_report', sa.Text(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_security_report', sa.Text(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_privacy_report', sa.Text(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_threat_model', sa.JSON(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_vuln_scan_result', sa.JSON(), nullable=True))
    op.add_column('reverse_engineering_reports', 
        sa.Column('ai_chat_history', sa.JSON(), nullable=True))


def downgrade() -> None:
    # Remove AI-Generated Report columns
    op.drop_column('reverse_engineering_reports', 'ai_chat_history')
    op.drop_column('reverse_engineering_reports', 'ai_vuln_scan_result')
    op.drop_column('reverse_engineering_reports', 'ai_threat_model')
    op.drop_column('reverse_engineering_reports', 'ai_privacy_report')
    op.drop_column('reverse_engineering_reports', 'ai_security_report')
    op.drop_column('reverse_engineering_reports', 'ai_functionality_report')
    
    # Remove JADX Full Scan columns
    op.drop_column('reverse_engineering_reports', 'jadx_data')
    op.drop_column('reverse_engineering_reports', 'jadx_total_files')
    op.drop_column('reverse_engineering_reports', 'jadx_total_classes')
