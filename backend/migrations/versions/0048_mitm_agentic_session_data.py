"""Add agentic session data fields to MITM reports

Revision ID: 0048_mitm_agentic_data
Revises: 0047_mitm_agent_memory
Create Date: 2026-01-23

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0048_mitm_agentic_data'
down_revision = '0047_mitm_agent_memory'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns for agentic session persistence
    op.add_column('mitm_analysis_reports', sa.Column('phases_executed', sa.JSON(), nullable=True))
    op.add_column('mitm_analysis_reports', sa.Column('mitre_techniques', sa.JSON(), nullable=True))
    op.add_column('mitm_analysis_reports', sa.Column('attack_chains_executed', sa.JSON(), nullable=True))
    op.add_column('mitm_analysis_reports', sa.Column('reasoning_traces', sa.JSON(), nullable=True))
    op.add_column('mitm_analysis_reports', sa.Column('captured_data', sa.JSON(), nullable=True))
    op.add_column('mitm_analysis_reports', sa.Column('execution_log', sa.JSON(), nullable=True))


def downgrade():
    op.drop_column('mitm_analysis_reports', 'execution_log')
    op.drop_column('mitm_analysis_reports', 'captured_data')
    op.drop_column('mitm_analysis_reports', 'reasoning_traces')
    op.drop_column('mitm_analysis_reports', 'attack_chains_executed')
    op.drop_column('mitm_analysis_reports', 'mitre_techniques')
    op.drop_column('mitm_analysis_reports', 'phases_executed')
