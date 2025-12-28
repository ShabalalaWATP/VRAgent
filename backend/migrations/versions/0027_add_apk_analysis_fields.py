"""Add APK analysis fields for decompiled code findings, CVE scan, and vulnerability hooks

Revision ID: 0027_apk_analysis_fields
Revises: 0026_doc_analysis_reports
Create Date: 2024-12-18

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0027_apk_analysis_fields'
down_revision = '0026_doc_analysis_reports'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add decompiled code analysis columns
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('decompiled_code_findings', sa.JSON(), nullable=True)
    )
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('decompiled_code_summary', sa.JSON(), nullable=True)
    )
    
    # Add CVE scan results column
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('cve_scan_results', sa.JSON(), nullable=True)
    )
    
    # Add vulnerability-specific Frida hooks column
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('vulnerability_frida_hooks', sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    # Remove added columns
    op.drop_column('reverse_engineering_reports', 'vulnerability_frida_hooks')
    op.drop_column('reverse_engineering_reports', 'cve_scan_results')
    op.drop_column('reverse_engineering_reports', 'decompiled_code_summary')
    op.drop_column('reverse_engineering_reports', 'decompiled_code_findings')
