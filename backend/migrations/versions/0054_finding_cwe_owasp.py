"""Add CWE and OWASP columns to findings table

Revision ID: 0054_finding_cwe_owasp
Revises: 0053_user_docker_allowlist
Create Date: 2026-01-30

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0054_finding_cwe_owasp'
down_revision = '0053_user_docker_allowlist'
branch_labels = None
depends_on = None


def upgrade():
    # Add cwe_ids column (array of strings for multiple CWEs per finding)
    op.add_column(
        'findings',
        sa.Column('cwe_ids', postgresql.ARRAY(sa.String()), nullable=True)
    )

    # Add owasp_category column (single OWASP Top 10 category)
    op.add_column(
        'findings',
        sa.Column('owasp_category', sa.String(), nullable=True)
    )

    # Create GIN index on cwe_ids for efficient array containment queries
    # e.g., WHERE 'CWE-89' = ANY(cwe_ids)
    op.create_index(
        'ix_findings_cwe_ids',
        'findings',
        ['cwe_ids'],
        postgresql_using='gin'
    )

    # Create B-tree index on owasp_category for filtering
    op.create_index(
        'ix_findings_owasp_category',
        'findings',
        ['owasp_category']
    )


def downgrade():
    op.drop_index('ix_findings_owasp_category', 'findings')
    op.drop_index('ix_findings_cwe_ids', 'findings')
    op.drop_column('findings', 'owasp_category')
    op.drop_column('findings', 'cwe_ids')
