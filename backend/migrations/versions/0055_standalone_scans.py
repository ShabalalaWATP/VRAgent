"""Add standalone scan support

Revision ID: 0055_standalone_scans
Revises: 0054_finding_cwe_owasp
Create Date: 2026-01-31

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0055_standalone_scans'
down_revision = '0054_finding_cwe_owasp'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Make project_id nullable on scan_runs
    op.alter_column('scan_runs', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=True)

    # Add standalone scan fields to scan_runs
    op.add_column('scan_runs', sa.Column('standalone_name', sa.String(), nullable=True))
    op.add_column('scan_runs', sa.Column('standalone_source_path', sa.String(), nullable=True))
    op.add_column('scan_runs', sa.Column('user_id', sa.Integer(), nullable=True))

    # Add foreign key for user_id
    op.create_foreign_key('fk_scan_runs_user_id', 'scan_runs', 'users', ['user_id'], ['id'])

    # Create index on user_id for standalone scan queries
    op.create_index('ix_scan_runs_user_id', 'scan_runs', ['user_id'])

    # Make project_id nullable on reports
    op.alter_column('reports', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=True)


def downgrade() -> None:
    # Remove index
    op.drop_index('ix_scan_runs_user_id', table_name='scan_runs')

    # Remove foreign key
    op.drop_constraint('fk_scan_runs_user_id', 'scan_runs', type_='foreignkey')

    # Remove standalone columns
    op.drop_column('scan_runs', 'user_id')
    op.drop_column('scan_runs', 'standalone_source_path')
    op.drop_column('scan_runs', 'standalone_name')

    # Make project_id non-nullable again (only if no nulls exist)
    op.alter_column('scan_runs', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=False)

    op.alter_column('reports', 'project_id',
                    existing_type=sa.Integer(),
                    nullable=False)
