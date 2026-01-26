"""Add coverage history and per-input coverage tables

Revision ID: 0039_coverage_history
Revises: 0038_hybrid_fuzzing_sessions
Create Date: 2026-01-15 14:00:00.000000

Adds tables for:
- Coverage time-series data (coverage_history)
- Per-input coverage data (input_coverage)
- Module coverage breakdown (module_coverage)
- Coverage bitmap snapshot on fuzzing_sessions
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0039_coverage_history'
down_revision = '0038_hybrid_fuzzing_sessions'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ==========================================================================
    # Coverage History Table - stores time-series coverage data
    # ==========================================================================
    op.create_table(
        'coverage_history',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, index=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('elapsed_sec', sa.Float(), nullable=False),
        sa.Column('total_edges', sa.Integer(), nullable=False, default=0),
        sa.Column('new_edges', sa.Integer(), nullable=False, default=0),
        sa.Column('total_blocks', sa.Integer(), nullable=True),
        sa.Column('bitmap_density', sa.Float(), nullable=True),
        sa.Column('exec_count', sa.BigInteger(), nullable=True),
        sa.Column('corpus_size', sa.Integer(), nullable=True),
        sa.Column('crash_count', sa.Integer(), nullable=True),
        sa.Column('hang_count', sa.Integer(), nullable=True),
        sa.Column('growth_rate', sa.Float(), nullable=True),  # edges per second
    )

    # Composite index for efficient time-range queries
    op.create_index(
        'ix_coverage_history_session_time',
        'coverage_history',
        ['session_id', 'timestamp'],
        unique=False
    )

    # ==========================================================================
    # Input Coverage Table - per-input coverage data
    # ==========================================================================
    op.create_table(
        'input_coverage',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, index=True),
        sa.Column('input_hash', sa.String(64), nullable=False),  # SHA256 hash
        sa.Column('input_path', sa.String(512), nullable=True),
        sa.Column('input_name', sa.String(256), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('edge_count', sa.Integer(), nullable=False, default=0),
        sa.Column('unique_edges', sa.Integer(), nullable=False, default=0),
        sa.Column('new_edges_added', sa.Integer(), nullable=False, default=0),
        sa.Column('bitmap_hash', sa.String(64), nullable=True),  # Hash of bitmap
        # Store edge IDs as JSON array (for smaller sets) or reference bitmap
        sa.Column('edge_ids', postgresql.JSON(), nullable=True),
        sa.Column('favored', sa.Boolean(), default=False),
        sa.Column('depth', sa.Integer(), nullable=True),  # AFL depth metric
        sa.Column('perf_score', sa.Float(), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('source', sa.String(64), nullable=True),  # manual, afl, concolic, taint
    )

    # Unique constraint for session + input hash
    op.create_index(
        'ix_input_coverage_session_hash',
        'input_coverage',
        ['session_id', 'input_hash'],
        unique=True
    )

    # Index for finding favored inputs
    op.create_index(
        'ix_input_coverage_favored',
        'input_coverage',
        ['session_id', 'favored'],
        unique=False
    )

    # ==========================================================================
    # Module Coverage Table - per-module/library coverage breakdown
    # ==========================================================================
    op.create_table(
        'module_coverage',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, index=True),
        sa.Column('module_name', sa.String(512), nullable=False),
        sa.Column('module_path', sa.String(1024), nullable=True),
        sa.Column('base_address', sa.BigInteger(), nullable=True),
        sa.Column('module_size', sa.BigInteger(), nullable=True),
        sa.Column('blocks_total', sa.Integer(), nullable=True),  # Total blocks in module
        sa.Column('blocks_covered', sa.Integer(), nullable=False, default=0),
        sa.Column('edges_covered', sa.Integer(), nullable=True),
        sa.Column('coverage_pct', sa.Float(), nullable=False, default=0.0),
        sa.Column('is_main_binary', sa.Boolean(), default=False),
        # Hotspots: [{"address": int, "hits": int, "function": str}, ...]
        sa.Column('hotspots', postgresql.JSON(), nullable=True),
        # Function coverage: {"func_name": {"covered": bool, "blocks": int}, ...}
        sa.Column('function_coverage', postgresql.JSON(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Unique constraint for session + module
    op.create_index(
        'ix_module_coverage_session_module',
        'module_coverage',
        ['session_id', 'module_name'],
        unique=True
    )

    # ==========================================================================
    # Coverage Gap Table - tracks uncovered regions for targeting
    # ==========================================================================
    op.create_table(
        'coverage_gaps',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, index=True),
        sa.Column('module_name', sa.String(512), nullable=True),
        sa.Column('function_name', sa.String(512), nullable=True),
        sa.Column('start_address', sa.BigInteger(), nullable=True),
        sa.Column('end_address', sa.BigInteger(), nullable=True),
        sa.Column('gap_size_blocks', sa.Integer(), nullable=True),
        sa.Column('priority', sa.Float(), nullable=True),  # 0-1 priority score
        sa.Column('reason', sa.String(256), nullable=True),  # why it's interesting
        sa.Column('reached_by_input', sa.String(64), nullable=True),  # input that got closest
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_index(
        'ix_coverage_gaps_session_priority',
        'coverage_gaps',
        ['session_id', 'priority'],
        unique=False
    )

    # ==========================================================================
    # Add coverage columns to fuzzing_sessions
    # ==========================================================================

    # Store final coverage bitmap (compressed/encoded)
    op.add_column(
        'fuzzing_sessions',
        sa.Column('coverage_bitmap', sa.LargeBinary(), nullable=True)
    )

    # Coverage statistics JSON
    # Structure: {
    #   "total_edges": int,
    #   "total_blocks": int,
    #   "bitmap_density": float,
    #   "peak_growth_rate": float,
    #   "plateau_time_sec": float or null,
    #   "estimated_saturation": float or null,
    #   "modules_covered": int,
    #   "functions_covered": int
    # }
    op.add_column(
        'fuzzing_sessions',
        sa.Column('coverage_stats', postgresql.JSON(), nullable=True)
    )

    # Coverage mode used (bitmap, qemu, ptrace, etc.)
    op.add_column(
        'fuzzing_sessions',
        sa.Column('coverage_mode', sa.String(64), nullable=True)
    )

    # Whether QEMU coverage was used
    op.add_column(
        'fuzzing_sessions',
        sa.Column('qemu_coverage_enabled', sa.Boolean(), nullable=True, server_default='false')
    )


def downgrade() -> None:
    # Drop columns from fuzzing_sessions
    op.drop_column('fuzzing_sessions', 'qemu_coverage_enabled')
    op.drop_column('fuzzing_sessions', 'coverage_mode')
    op.drop_column('fuzzing_sessions', 'coverage_stats')
    op.drop_column('fuzzing_sessions', 'coverage_bitmap')

    # Drop coverage_gaps table
    op.drop_index('ix_coverage_gaps_session_priority', table_name='coverage_gaps')
    op.drop_table('coverage_gaps')

    # Drop module_coverage table
    op.drop_index('ix_module_coverage_session_module', table_name='module_coverage')
    op.drop_table('module_coverage')

    # Drop input_coverage table
    op.drop_index('ix_input_coverage_favored', table_name='input_coverage')
    op.drop_index('ix_input_coverage_session_hash', table_name='input_coverage')
    op.drop_table('input_coverage')

    # Drop coverage_history table
    op.drop_index('ix_coverage_history_session_time', table_name='coverage_history')
    op.drop_table('coverage_history')
