"""Add agentic binary fuzzer tables

Revision ID: 0041
Revises: 0040
Create Date: 2025-01-18

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0041'
down_revision = '0040'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Agentic binary fuzzing campaigns
    op.create_table(
        'agentic_binary_campaigns',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('binary_hash', sa.String(64), nullable=False),
        sa.Column('binary_name', sa.String(256), nullable=False),
        sa.Column('binary_path', sa.Text(), nullable=True),

        # AI-generated analysis
        sa.Column('campaign_plan', postgresql.JSON(), nullable=True),
        sa.Column('binary_profile', postgresql.JSON(), nullable=True),

        # Status and strategy
        sa.Column('status', sa.String(32), nullable=False, default='initializing'),
        sa.Column('current_strategy', sa.String(64), nullable=True),

        # Campaign metrics
        sa.Column('total_executions', sa.BigInteger(), default=0),
        sa.Column('coverage_percentage', sa.Float(), default=0.0),
        sa.Column('edges_discovered', sa.Integer(), default=0),
        sa.Column('edges_total', sa.Integer(), default=0),
        sa.Column('corpus_size', sa.Integer(), default=0),
        sa.Column('unique_crashes', sa.Integer(), default=0),
        sa.Column('exploitable_crashes', sa.Integer(), default=0),

        # AI decision metrics
        sa.Column('total_decisions', sa.Integer(), default=0),
        sa.Column('strategy_changes', sa.Integer(), default=0),
        sa.Column('effective_decisions', sa.Integer(), default=0),

        # Performance metrics
        sa.Column('peak_execs_per_sec', sa.Float(), default=0.0),
        sa.Column('avg_execs_per_sec', sa.Float(), default=0.0),

        # Configuration
        sa.Column('config_json', postgresql.JSON(), nullable=True),
        sa.Column('engine_count', sa.Integer(), default=1),

        # Timestamps
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_checkpoint', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # AI decisions log
    op.create_table(
        'agentic_campaign_decisions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('agentic_binary_campaigns.campaign_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('decision_id', sa.String(64), nullable=False),

        # Decision details
        sa.Column('decision_type', sa.String(64), nullable=False),
        sa.Column('reasoning', sa.Text(), nullable=True),
        sa.Column('parameters', postgresql.JSON(), nullable=True),
        sa.Column('priority', sa.Integer(), default=5),

        # Context at decision time
        sa.Column('coverage_at_decision', sa.Float(), nullable=True),
        sa.Column('crashes_at_decision', sa.Integer(), nullable=True),
        sa.Column('exec_per_sec_at_decision', sa.Float(), nullable=True),
        sa.Column('elapsed_time_sec', sa.Integer(), nullable=True),

        # Outcome tracking
        sa.Column('executed', sa.Boolean(), default=False),
        sa.Column('execution_result', sa.Text(), nullable=True),
        sa.Column('outcome', sa.String(32), nullable=True),  # effective, ineffective, pending
        sa.Column('impact_coverage_delta', sa.Float(), nullable=True),
        sa.Column('impact_crashes_delta', sa.Integer(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
    )

    # AI-triaged crashes
    op.create_table(
        'agentic_triaged_crashes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('agentic_binary_campaigns.campaign_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('crash_id', sa.String(64), nullable=False, index=True),
        sa.Column('crash_hash', sa.String(64), nullable=False, index=True),

        # Crash information
        sa.Column('crash_type', sa.String(64), nullable=False),
        sa.Column('crash_address', sa.String(32), nullable=True),
        sa.Column('crash_instruction', sa.String(256), nullable=True),
        sa.Column('access_type', sa.String(32), nullable=True),  # read, write, execute

        # AI analysis results
        sa.Column('exploitability', sa.String(32), nullable=False),
        sa.Column('confidence', sa.Float(), default=0.5),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('exploit_primitives', postgresql.JSON(), nullable=True),
        sa.Column('similar_cves', postgresql.JSON(), nullable=True),

        # AI reasoning
        sa.Column('analysis_reasoning', sa.Text(), nullable=True),
        sa.Column('mitigation_bypasses', postgresql.JSON(), nullable=True),

        # Exploit development
        sa.Column('exploit_skeleton', sa.Text(), nullable=True),
        sa.Column('rop_gadgets_found', sa.Integer(), default=0),
        sa.Column('exploit_technique', sa.String(64), nullable=True),
        sa.Column('bypass_suggestions', postgresql.JSON(), nullable=True),

        # Input details
        sa.Column('input_hash', sa.String(64), nullable=True),
        sa.Column('input_size', sa.Integer(), nullable=True),
        sa.Column('input_preview', sa.Text(), nullable=True),  # First N bytes as hex

        # Register state (if available)
        sa.Column('registers_json', postgresql.JSON(), nullable=True),
        sa.Column('stack_trace_json', postgresql.JSON(), nullable=True),

        # Timestamps
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('triaged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Campaign checkpoints (for persistence/recovery)
    op.create_table(
        'agentic_campaign_checkpoints',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('agentic_binary_campaigns.campaign_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('checkpoint_id', sa.String(64), nullable=False),

        # State snapshot
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('current_strategy', sa.String(64), nullable=True),
        sa.Column('elapsed_time_sec', sa.Integer(), nullable=True),

        # Metrics snapshot
        sa.Column('total_executions', sa.BigInteger(), default=0),
        sa.Column('coverage_percentage', sa.Float(), default=0.0),
        sa.Column('unique_crashes', sa.Integer(), default=0),
        sa.Column('exploitable_crashes', sa.Integer(), default=0),
        sa.Column('decisions_made', sa.Integer(), default=0),
        sa.Column('corpus_size', sa.Integer(), default=0),

        # Engine states
        sa.Column('engine_states_json', postgresql.JSON(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Binary profiles (cached analysis)
    op.create_table(
        'agentic_binary_profiles',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('binary_hash', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('binary_name', sa.String(256), nullable=True),

        # Basic info
        sa.Column('file_type', sa.String(32), nullable=True),  # ELF, PE, Mach-O
        sa.Column('architecture', sa.String(32), nullable=True),  # x86, x64, ARM
        sa.Column('size_bytes', sa.Integer(), nullable=True),

        # Security features
        sa.Column('has_aslr', sa.Boolean(), default=True),
        sa.Column('has_dep', sa.Boolean(), default=True),
        sa.Column('has_stack_canary', sa.Boolean(), default=False),
        sa.Column('has_pie', sa.Boolean(), default=False),
        sa.Column('relro_type', sa.String(16), nullable=True),  # none, partial, full

        # Analysis results
        sa.Column('function_count', sa.Integer(), default=0),
        sa.Column('import_count', sa.Integer(), default=0),
        sa.Column('export_count', sa.Integer(), default=0),
        sa.Column('dangerous_function_count', sa.Integer(), default=0),
        sa.Column('attack_surface_score', sa.Float(), default=0.0),

        # Detailed analysis (JSON)
        sa.Column('imports_json', postgresql.JSON(), nullable=True),
        sa.Column('exports_json', postgresql.JSON(), nullable=True),
        sa.Column('dangerous_functions_json', postgresql.JSON(), nullable=True),
        sa.Column('input_handlers_json', postgresql.JSON(), nullable=True),
        sa.Column('vulnerability_hints_json', postgresql.JSON(), nullable=True),
        sa.Column('interesting_strings_json', postgresql.JSON(), nullable=True),

        # AI enhancement
        sa.Column('ai_analysis_json', postgresql.JSON(), nullable=True),
        sa.Column('recommended_strategy', sa.String(64), nullable=True),
        sa.Column('estimated_difficulty', sa.String(32), nullable=True),

        # Timestamps
        sa.Column('analyzed_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('ai_enhanced_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Generated seeds and dictionary entries
    op.create_table(
        'agentic_generated_seeds',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('agentic_binary_campaigns.campaign_id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('binary_hash', sa.String(64), nullable=True, index=True),

        sa.Column('seed_hash', sa.String(64), nullable=False),
        sa.Column('seed_name', sa.String(128), nullable=True),
        sa.Column('seed_size', sa.Integer(), nullable=True),
        sa.Column('detected_format', sa.String(64), nullable=True),
        sa.Column('generation_method', sa.String(64), nullable=True),  # ai_generated, corpus_splice, format_specific
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('expected_path', sa.Text(), nullable=True),

        # Effectiveness tracking
        sa.Column('coverage_increase', sa.Float(), nullable=True),
        sa.Column('found_crash', sa.Boolean(), default=False),
        sa.Column('is_interesting', sa.Boolean(), default=False),

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Coverage snapshots for trend analysis
    op.create_table(
        'agentic_coverage_snapshots',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('agentic_binary_campaigns.campaign_id', ondelete='CASCADE'), nullable=False, index=True),

        sa.Column('coverage_percentage', sa.Float(), nullable=False),
        sa.Column('edges_discovered', sa.Integer(), default=0),
        sa.Column('total_executions', sa.BigInteger(), default=0),
        sa.Column('corpus_size', sa.Integer(), default=0),
        sa.Column('execs_per_sec', sa.Float(), default=0.0),
        sa.Column('unique_crashes', sa.Integer(), default=0),
        sa.Column('current_strategy', sa.String(64), nullable=True),

        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for better query performance
    op.create_index('ix_agentic_campaigns_status', 'agentic_binary_campaigns', ['status'])
    op.create_index('ix_agentic_campaigns_binary', 'agentic_binary_campaigns', ['binary_hash'])
    op.create_index('ix_agentic_decisions_type', 'agentic_campaign_decisions', ['decision_type'])
    op.create_index('ix_agentic_crashes_exploitability', 'agentic_triaged_crashes', ['exploitability'])
    op.create_index('ix_agentic_crashes_type', 'agentic_triaged_crashes', ['crash_type'])
    op.create_index('ix_agentic_coverage_timestamp', 'agentic_coverage_snapshots', ['timestamp'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_agentic_coverage_timestamp')
    op.drop_index('ix_agentic_crashes_type')
    op.drop_index('ix_agentic_crashes_exploitability')
    op.drop_index('ix_agentic_decisions_type')
    op.drop_index('ix_agentic_campaigns_binary')
    op.drop_index('ix_agentic_campaigns_status')

    # Drop tables
    op.drop_table('agentic_coverage_snapshots')
    op.drop_table('agentic_generated_seeds')
    op.drop_table('agentic_binary_profiles')
    op.drop_table('agentic_campaign_checkpoints')
    op.drop_table('agentic_triaged_crashes')
    op.drop_table('agentic_campaign_decisions')
    op.drop_table('agentic_binary_campaigns')
