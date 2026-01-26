"""Add binary_fuzzer_sessions table for persisting AFL++/binary fuzzing data

Revision ID: 0042
Revises: 0041
Create Date: 2026-01-19

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0042_binary_fuzzer_sessions'
down_revision = '0041b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'binary_fuzzer_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        
        # Session metadata
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('binary_path', sa.String(), nullable=False),
        sa.Column('binary_name', sa.String(), nullable=True),
        sa.Column('architecture', sa.String(), nullable=True),
        
        # Configuration
        sa.Column('mode', sa.String(), nullable=False, server_default='coverage'),
        sa.Column('mutation_strategy', sa.String(), nullable=True),
        sa.Column('input_format', sa.String(), nullable=True),
        sa.Column('timeout_ms', sa.Integer(), nullable=True),
        sa.Column('memory_limit_mb', sa.Integer(), nullable=True),
        
        # Status
        sa.Column('status', sa.String(), nullable=False, server_default='created'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('stopped_at', sa.DateTime(timezone=True), nullable=True),
        
        # Statistics
        sa.Column('total_executions', sa.Integer(), server_default='0'),
        sa.Column('executions_per_second', sa.Float(), nullable=True),
        sa.Column('total_crashes', sa.Integer(), server_default='0'),
        sa.Column('unique_crashes', sa.Integer(), server_default='0'),
        sa.Column('hangs', sa.Integer(), server_default='0'),
        sa.Column('coverage_edges', sa.Integer(), server_default='0'),
        sa.Column('coverage_percentage', sa.Float(), nullable=True),
        sa.Column('corpus_size', sa.Integer(), server_default='0'),
        
        # Findings by severity
        sa.Column('crashes_critical', sa.Integer(), server_default='0'),
        sa.Column('crashes_high', sa.Integer(), server_default='0'),
        sa.Column('crashes_medium', sa.Integer(), server_default='0'),
        sa.Column('crashes_low', sa.Integer(), server_default='0'),
        
        # Detailed data (JSON)
        sa.Column('crashes', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('coverage_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('corpus_entries', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('memory_errors', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        
        # AI Analysis
        sa.Column('ai_analysis', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        
        # Primary key and foreign keys
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    )
    
    # Create indexes
    op.create_index('ix_binary_fuzzer_sessions_id', 'binary_fuzzer_sessions', ['id'])
    op.create_index('ix_binary_fuzzer_sessions_session_id', 'binary_fuzzer_sessions', ['session_id'], unique=True)
    op.create_index('ix_binary_fuzzer_sessions_project_id', 'binary_fuzzer_sessions', ['project_id'])
    op.create_index('ix_binary_fuzzer_sessions_user_id', 'binary_fuzzer_sessions', ['user_id'])
    op.create_index('ix_binary_fuzzer_sessions_status', 'binary_fuzzer_sessions', ['status'])
    op.create_index('ix_binary_fuzzer_sessions_created_at', 'binary_fuzzer_sessions', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_binary_fuzzer_sessions_created_at')
    op.drop_index('ix_binary_fuzzer_sessions_status')
    op.drop_index('ix_binary_fuzzer_sessions_user_id')
    op.drop_index('ix_binary_fuzzer_sessions_project_id')
    op.drop_index('ix_binary_fuzzer_sessions_session_id')
    op.drop_index('ix_binary_fuzzer_sessions_id')
    op.drop_table('binary_fuzzer_sessions')
