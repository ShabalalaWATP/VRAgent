"""Add protocol fuzzing, grammar, and format fuzzing tables

Revision ID: 0040
Revises: 0039
Create Date: 2025-01-18

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0040'
down_revision = '0039_coverage_history'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Protocol fuzzing sessions table
    op.create_table(
        'protocol_fuzz_sessions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('target_host', sa.String(256), nullable=False),
        sa.Column('target_port', sa.Integer(), nullable=False),
        sa.Column('transport', sa.String(16), nullable=False),  # tcp, udp
        sa.Column('protocol_name', sa.String(64), nullable=True),  # e.g., http, ftp, smtp
        sa.Column('ssl_enabled', sa.Boolean(), default=False),
        sa.Column('messages_sent', sa.Integer(), default=0),
        sa.Column('responses_received', sa.Integer(), default=0),
        sa.Column('crashes_detected', sa.Integer(), default=0),
        sa.Column('timeouts', sa.Integer(), default=0),
        sa.Column('interesting_count', sa.Integer(), default=0),
        sa.Column('status', sa.String(32), default='pending'),  # pending, running, completed, error
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('config_json', postgresql.JSON(), nullable=True),  # Full config
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_sec', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Protocol fuzzing events (interesting responses, crashes, etc.)
    op.create_table(
        'protocol_fuzz_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), sa.ForeignKey('protocol_fuzz_sessions.session_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('event_type', sa.String(32), nullable=False),  # send, receive, crash, timeout, interesting
        sa.Column('payload_hash', sa.String(64), nullable=True),  # MD5 of payload
        sa.Column('payload_size', sa.Integer(), nullable=True),
        sa.Column('response_size', sa.Integer(), nullable=True),
        sa.Column('protocol_state', sa.String(64), nullable=True),  # State machine state
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('details_json', postgresql.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Grammar definitions table
    op.create_table(
        'grammar_definitions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(128), unique=True, nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('start_symbol', sa.String(64), nullable=False),
        sa.Column('grammar_json', postgresql.JSON(), nullable=False),  # Full grammar definition
        sa.Column('is_builtin', sa.Boolean(), default=False),
        sa.Column('created_by', sa.String(128), nullable=True),  # User who created it
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )

    # Grammar fuzzing sessions
    op.create_table(
        'grammar_fuzz_sessions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('grammar_id', sa.Integer(), sa.ForeignKey('grammar_definitions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('grammar_name', sa.String(128), nullable=True),  # For built-in grammars
        sa.Column('inputs_generated', sa.Integer(), default=0),
        sa.Column('mutations_applied', sa.Integer(), default=0),
        sa.Column('crossovers_applied', sa.Integer(), default=0),
        sa.Column('interesting_found', sa.Integer(), default=0),
        sa.Column('status', sa.String(32), default='pending'),
        sa.Column('config_json', postgresql.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Format fuzzing sessions
    op.create_table(
        'format_fuzz_sessions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('format_type', sa.String(32), nullable=False),  # png, pdf, zip, etc.
        sa.Column('seed_hash', sa.String(64), nullable=True),  # Hash of seed file
        sa.Column('seed_size', sa.Integer(), nullable=True),
        sa.Column('mutations_generated', sa.Integer(), default=0),
        sa.Column('crashes_found', sa.Integer(), default=0),
        sa.Column('interesting_found', sa.Integer(), default=0),
        sa.Column('checksums_fixed', sa.Integer(), default=0),
        sa.Column('sizes_fixed', sa.Integer(), default=0),
        sa.Column('status', sa.String(32), default='pending'),
        sa.Column('config_json', postgresql.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Format mutations log
    op.create_table(
        'format_mutations',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), sa.ForeignKey('format_fuzz_sessions.session_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('mutation_type', sa.String(64), nullable=False),  # field_mutation, chunk_mutation, etc.
        sa.Column('field_mutated', sa.String(64), nullable=True),
        sa.Column('chunk_mutated', sa.String(64), nullable=True),
        sa.Column('original_hash', sa.String(64), nullable=True),
        sa.Column('mutated_hash', sa.String(64), nullable=True),
        sa.Column('original_size', sa.Integer(), nullable=True),
        sa.Column('mutated_size', sa.Integer(), nullable=True),
        sa.Column('checksum_fixed', sa.Boolean(), default=False),
        sa.Column('is_interesting', sa.Boolean(), default=False),
        sa.Column('is_crash', sa.Boolean(), default=False),
        sa.Column('details_json', postgresql.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Custom protocol definitions (user-defined protocols)
    op.create_table(
        'custom_protocols',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(128), unique=True, nullable=False),
        sa.Column('transport', sa.String(16), nullable=False),  # tcp, udp
        sa.Column('default_port', sa.Integer(), nullable=True),
        sa.Column('message_format', sa.String(32), default='text'),  # text, binary, mixed
        sa.Column('line_ending', sa.String(16), default='\\r\\n'),
        sa.Column('initial_state', sa.String(64), nullable=False),
        sa.Column('states_json', postgresql.JSON(), nullable=False),  # State machine definition
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_builtin', sa.Boolean(), default=False),
        sa.Column('created_by', sa.String(128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )

    # Create indexes for better query performance
    op.create_index('ix_protocol_fuzz_sessions_status', 'protocol_fuzz_sessions', ['status'])
    op.create_index('ix_protocol_fuzz_sessions_protocol', 'protocol_fuzz_sessions', ['protocol_name'])
    op.create_index('ix_protocol_fuzz_events_type', 'protocol_fuzz_events', ['event_type'])
    op.create_index('ix_grammar_fuzz_sessions_status', 'grammar_fuzz_sessions', ['status'])
    op.create_index('ix_format_fuzz_sessions_status', 'format_fuzz_sessions', ['status'])
    op.create_index('ix_format_fuzz_sessions_format', 'format_fuzz_sessions', ['format_type'])
    op.create_index('ix_format_mutations_type', 'format_mutations', ['mutation_type'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_format_mutations_type')
    op.drop_index('ix_format_fuzz_sessions_format')
    op.drop_index('ix_format_fuzz_sessions_status')
    op.drop_index('ix_grammar_fuzz_sessions_status')
    op.drop_index('ix_protocol_fuzz_events_type')
    op.drop_index('ix_protocol_fuzz_sessions_protocol')
    op.drop_index('ix_protocol_fuzz_sessions_status')

    # Drop tables
    op.drop_table('custom_protocols')
    op.drop_table('format_mutations')
    op.drop_table('format_fuzz_sessions')
    op.drop_table('grammar_fuzz_sessions')
    op.drop_table('grammar_definitions')
    op.drop_table('protocol_fuzz_events')
    op.drop_table('protocol_fuzz_sessions')
