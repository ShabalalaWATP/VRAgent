"""Add project_id to network analysis tables.

Revision ID: 0011_network_project
Revises: 0010
Create Date: 2025-01-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0011_network_project'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add project_id column to network_analysis_reports
    op.add_column(
        'network_analysis_reports',
        sa.Column('project_id', sa.Integer(), nullable=True)
    )
    op.create_index(
        'ix_network_analysis_reports_project_id',
        'network_analysis_reports',
        ['project_id']
    )
    op.create_foreign_key(
        'fk_network_analysis_reports_project_id',
        'network_analysis_reports',
        'projects',
        ['project_id'],
        ['id'],
        ondelete='SET NULL'
    )
    
    # Add project_id column to fuzzing_sessions
    op.add_column(
        'fuzzing_sessions',
        sa.Column('project_id', sa.Integer(), nullable=True)
    )
    op.create_index(
        'ix_fuzzing_sessions_project_id',
        'fuzzing_sessions',
        ['project_id']
    )
    op.create_foreign_key(
        'fk_fuzzing_sessions_project_id',
        'fuzzing_sessions',
        'projects',
        ['project_id'],
        ['id'],
        ondelete='SET NULL'
    )


def downgrade() -> None:
    # Remove from fuzzing_sessions
    op.drop_constraint('fk_fuzzing_sessions_project_id', 'fuzzing_sessions', type_='foreignkey')
    op.drop_index('ix_fuzzing_sessions_project_id', table_name='fuzzing_sessions')
    op.drop_column('fuzzing_sessions', 'project_id')
    
    # Remove from network_analysis_reports
    op.drop_constraint('fk_network_analysis_reports_project_id', 'network_analysis_reports', type_='foreignkey')
    op.drop_index('ix_network_analysis_reports_project_id', table_name='network_analysis_reports')
    op.drop_column('network_analysis_reports', 'project_id')
