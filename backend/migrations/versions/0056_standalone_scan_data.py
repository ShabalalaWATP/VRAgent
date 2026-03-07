"""Add scan_run_id to code_chunks, dependencies, vulnerabilities for standalone scans

Revision ID: 0056_standalone_scan_data
Revises: 0055_standalone_scans
Create Date: 2026-02-01

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0056_standalone_scan_data'
down_revision = '0055_standalone_scans'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add scan_run_id to code_chunks
    op.add_column('code_chunks', sa.Column('scan_run_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_code_chunks_scan_run_id', 'code_chunks', 'scan_runs', ['scan_run_id'], ['id'])
    op.create_index('ix_code_chunks_scan_run_id', 'code_chunks', ['scan_run_id'])

    # Add scan_run_id to dependencies
    op.add_column('dependencies', sa.Column('scan_run_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_dependencies_scan_run_id', 'dependencies', 'scan_runs', ['scan_run_id'], ['id'])
    op.create_index('ix_dependencies_scan_run_id', 'dependencies', ['scan_run_id'])

    # Add scan_run_id to vulnerabilities
    op.add_column('vulnerabilities', sa.Column('scan_run_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_vulnerabilities_scan_run_id', 'vulnerabilities', 'scan_runs', ['scan_run_id'], ['id'])
    op.create_index('ix_vulnerabilities_scan_run_id', 'vulnerabilities', ['scan_run_id'])


def downgrade() -> None:
    # Remove from vulnerabilities
    op.drop_index('ix_vulnerabilities_scan_run_id', table_name='vulnerabilities')
    op.drop_constraint('fk_vulnerabilities_scan_run_id', 'vulnerabilities', type_='foreignkey')
    op.drop_column('vulnerabilities', 'scan_run_id')

    # Remove from dependencies
    op.drop_index('ix_dependencies_scan_run_id', table_name='dependencies')
    op.drop_constraint('fk_dependencies_scan_run_id', 'dependencies', type_='foreignkey')
    op.drop_column('dependencies', 'scan_run_id')

    # Remove from code_chunks
    op.drop_index('ix_code_chunks_scan_run_id', table_name='code_chunks')
    op.drop_constraint('fk_code_chunks_scan_run_id', 'code_chunks', type_='foreignkey')
    op.drop_column('code_chunks', 'scan_run_id')
