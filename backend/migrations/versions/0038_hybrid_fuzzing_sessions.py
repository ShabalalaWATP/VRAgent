"""Add hybrid fuzzing fields to fuzzing sessions

Revision ID: 0038_hybrid_fuzzing_sessions
Revises: 0037_add_zap_scans
Create Date: 2026-01-15 12:00:00.000000

Adds fields for:
- Hybrid fuzzing mode (concolic, taint, LAF-Intel)
- Concolic execution statistics
- Taint tracking statistics
- Hot bytes mapping for targeted mutations
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0038_hybrid_fuzzing_sessions'
down_revision = '0037_add_zap_scans'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add hybrid fuzzing mode column
    op.add_column(
        'fuzzing_sessions',
        sa.Column('hybrid_mode', sa.String(), nullable=True)
    )

    # Add hybrid feature enable flags
    op.add_column(
        'fuzzing_sessions',
        sa.Column('concolic_enabled', sa.Boolean(), nullable=True, server_default='false')
    )
    op.add_column(
        'fuzzing_sessions',
        sa.Column('taint_enabled', sa.Boolean(), nullable=True, server_default='false')
    )
    op.add_column(
        'fuzzing_sessions',
        sa.Column('laf_enabled', sa.Boolean(), nullable=True, server_default='false')
    )

    # Add concolic execution statistics (JSON)
    # Structure: {
    #   "runs": int,
    #   "inputs_generated": int,
    #   "coverage_contributions": int,
    #   "constraints_collected": int,
    #   "constraints_solved": int,
    #   "solver_time_total_ms": float,
    #   "last_run": "ISO timestamp"
    # }
    op.add_column(
        'fuzzing_sessions',
        sa.Column('concolic_stats', postgresql.JSON(), nullable=True)
    )

    # Add taint tracking statistics (JSON)
    # Structure: {
    #   "analyses": int,
    #   "hot_bytes_identified": int,
    #   "guided_mutations": int,
    #   "sink_hits_total": int,
    #   "unique_sinks_reached": int,
    #   "last_run": "ISO timestamp"
    # }
    op.add_column(
        'fuzzing_sessions',
        sa.Column('taint_stats', postgresql.JSON(), nullable=True)
    )

    # Add hot bytes map for mutation guidance (JSON)
    # Structure: {
    #   "input_hash": [byte_offsets...],
    #   ...
    # }
    op.add_column(
        'fuzzing_sessions',
        sa.Column('hot_bytes_map', postgresql.JSON(), nullable=True)
    )

    # Add LAF-Intel instrumentation info (JSON)
    # Structure: {
    #   "instrumented_path": "path/to/binary",
    #   "modes": ["split_switches", "transform_compares"],
    #   "split_compares": int,
    #   "transformed_switches": int,
    #   "build_time": "ISO timestamp"
    # }
    op.add_column(
        'fuzzing_sessions',
        sa.Column('laf_intel_info', postgresql.JSON(), nullable=True)
    )

    # Add hybrid session reference (for orchestrator tracking)
    op.add_column(
        'fuzzing_sessions',
        sa.Column('hybrid_session_id', sa.String(), nullable=True)
    )

    # Create index for hybrid mode queries
    op.create_index(
        op.f('ix_fuzzing_sessions_hybrid_mode'),
        'fuzzing_sessions',
        ['hybrid_mode'],
        unique=False
    )


def downgrade() -> None:
    # Drop index
    op.drop_index(op.f('ix_fuzzing_sessions_hybrid_mode'), table_name='fuzzing_sessions')

    # Drop columns
    op.drop_column('fuzzing_sessions', 'hybrid_session_id')
    op.drop_column('fuzzing_sessions', 'laf_intel_info')
    op.drop_column('fuzzing_sessions', 'hot_bytes_map')
    op.drop_column('fuzzing_sessions', 'taint_stats')
    op.drop_column('fuzzing_sessions', 'concolic_stats')
    op.drop_column('fuzzing_sessions', 'laf_enabled')
    op.drop_column('fuzzing_sessions', 'taint_enabled')
    op.drop_column('fuzzing_sessions', 'concolic_enabled')
    op.drop_column('fuzzing_sessions', 'hybrid_mode')
