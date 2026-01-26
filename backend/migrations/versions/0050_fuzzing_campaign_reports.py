"""Add fuzzing_campaign_reports table for AI-generated campaign reports

Revision ID: 0050
Revises: 0049
Create Date: 2026-01-25

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0050_fuzzing_campaign_reports'
down_revision = '0049_mitm_auto_save'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'fuzzing_campaign_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('campaign_id', sa.String(64), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('project_id', sa.Integer(), nullable=True),

        # Binary info
        sa.Column('binary_name', sa.String(255), nullable=False),
        sa.Column('binary_hash', sa.String(64), nullable=True),
        sa.Column('binary_type', sa.String(32), nullable=True),
        sa.Column('architecture', sa.String(32), nullable=True),

        # Campaign metadata
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),

        # Key metrics
        sa.Column('total_executions', sa.BigInteger(), server_default='0'),
        sa.Column('executions_per_second', sa.Float(), nullable=True),
        sa.Column('final_coverage', sa.Float(), nullable=True),
        sa.Column('unique_crashes', sa.Integer(), server_default='0'),
        sa.Column('exploitable_crashes', sa.Integer(), server_default='0'),
        sa.Column('total_decisions', sa.Integer(), server_default='0'),

        # AI Report content (structured JSON)
        sa.Column('report_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),

        # Report sections (for quick access without parsing full JSON)
        sa.Column('executive_summary', sa.Text(), nullable=True),
        sa.Column('findings_summary', sa.Text(), nullable=True),
        sa.Column('recommendations', sa.Text(), nullable=True),

        # Full markdown report (pre-rendered for export)
        sa.Column('markdown_report', sa.Text(), nullable=True),

        # Decision history
        sa.Column('decisions', postgresql.JSON(astext_type=sa.Text()), nullable=True),

        # Crash details
        sa.Column('crashes', postgresql.JSON(astext_type=sa.Text()), nullable=True),

        # Coverage data
        sa.Column('coverage_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),

        # Primary key and foreign keys
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
    )

    # Create indexes
    op.create_index('ix_fuzzing_campaign_reports_id', 'fuzzing_campaign_reports', ['id'])
    op.create_index('ix_fuzzing_campaign_reports_campaign_id', 'fuzzing_campaign_reports', ['campaign_id'], unique=True)
    op.create_index('ix_fuzzing_campaign_reports_user_id', 'fuzzing_campaign_reports', ['user_id'])
    op.create_index('ix_fuzzing_campaign_reports_project_id', 'fuzzing_campaign_reports', ['project_id'])
    op.create_index('ix_fuzzing_campaign_reports_created_at', 'fuzzing_campaign_reports', ['created_at'])
    op.create_index('ix_fuzzing_campaign_reports_binary_name', 'fuzzing_campaign_reports', ['binary_name'])


def downgrade() -> None:
    op.drop_index('ix_fuzzing_campaign_reports_binary_name')
    op.drop_index('ix_fuzzing_campaign_reports_created_at')
    op.drop_index('ix_fuzzing_campaign_reports_project_id')
    op.drop_index('ix_fuzzing_campaign_reports_user_id')
    op.drop_index('ix_fuzzing_campaign_reports_campaign_id')
    op.drop_index('ix_fuzzing_campaign_reports_id')
    op.drop_table('fuzzing_campaign_reports')
