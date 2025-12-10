"""Add fuzzing sessions table

Revision ID: 0006_fuzzing_sessions
Revises: 0005_dns_report_data
Create Date: 2024-12-10 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0006_fuzzing_sessions'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create fuzzing_sessions table
    op.create_table(
        'fuzzing_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('target_url', sa.String(), nullable=False),
        sa.Column('method', sa.String(), nullable=False, server_default='GET'),
        sa.Column('status', sa.String(), nullable=False, server_default='created'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        
        # Configuration stored as JSON
        sa.Column('config', postgresql.JSON(), nullable=True),
        
        # Statistics
        sa.Column('total_requests', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('success_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('error_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('interesting_count', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('avg_response_time', sa.Float(), nullable=True),
        
        # Results stored as JSON (can be large)
        sa.Column('results', postgresql.JSON(), nullable=True),
        
        # Findings from smart detection
        sa.Column('findings', postgresql.JSON(), nullable=True),
        
        # Analysis results (WAF, rate limiting, etc.)
        sa.Column('analysis', postgresql.JSON(), nullable=True),
        
        # Tags for organization
        sa.Column('tags', postgresql.JSON(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_fuzzing_sessions_id'), 'fuzzing_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_fuzzing_sessions_status'), 'fuzzing_sessions', ['status'], unique=False)
    op.create_index(op.f('ix_fuzzing_sessions_target_url'), 'fuzzing_sessions', ['target_url'], unique=False)
    op.create_index(op.f('ix_fuzzing_sessions_created_at'), 'fuzzing_sessions', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_fuzzing_sessions_created_at'), table_name='fuzzing_sessions')
    op.drop_index(op.f('ix_fuzzing_sessions_target_url'), table_name='fuzzing_sessions')
    op.drop_index(op.f('ix_fuzzing_sessions_status'), table_name='fuzzing_sessions')
    op.drop_index(op.f('ix_fuzzing_sessions_id'), table_name='fuzzing_sessions')
    op.drop_table('fuzzing_sessions')
