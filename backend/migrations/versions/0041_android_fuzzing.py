"""Add Android fuzzing tables

Revision ID: 0041b
Revises: 0041
Create Date: 2025-01-18

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0041b'
down_revision = '0041'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ========================================================================
    # Android Devices Table
    # ========================================================================
    op.create_table(
        'android_devices',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('serial', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('model', sa.String(128), nullable=True),
        sa.Column('manufacturer', sa.String(128), nullable=True),
        sa.Column('android_version', sa.String(32), nullable=True),
        sa.Column('sdk_version', sa.Integer(), nullable=True),
        sa.Column('abi', sa.String(32), nullable=True),
        sa.Column('is_emulator', sa.Boolean(), default=False),
        sa.Column('is_rooted', sa.Boolean(), default=False),
        sa.Column('frida_installed', sa.Boolean(), default=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )

    # ========================================================================
    # Android Fuzzing Campaigns Table
    # ========================================================================
    op.create_table(
        'android_fuzz_campaigns',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('campaign_id', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('target_type', sa.String(32), nullable=False),  # apk, package, native_library
        sa.Column('target_path', sa.String(512), nullable=True),
        sa.Column('package_name', sa.String(256), nullable=True),
        sa.Column('device_serial', sa.String(64), nullable=True),

        # Status
        sa.Column('status', sa.String(32), default='created'),  # created, running, completed, failed
        sa.Column('current_phase', sa.String(64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),

        # Configuration
        sa.Column('config_json', postgresql.JSON(), nullable=True),

        # Statistics
        sa.Column('native_libraries_found', sa.Integer(), default=0),
        sa.Column('exported_components_found', sa.Integer(), default=0),
        sa.Column('native_executions', sa.Integer(), default=0),
        sa.Column('native_crashes', sa.Integer(), default=0),
        sa.Column('native_unique_crashes', sa.Integer(), default=0),
        sa.Column('intents_sent', sa.Integer(), default=0),
        sa.Column('intent_crashes', sa.Integer(), default=0),
        sa.Column('intent_unique_crashes', sa.Integer(), default=0),
        sa.Column('anrs_detected', sa.Integer(), default=0),
        sa.Column('total_unique_crashes', sa.Integer(), default=0),
        sa.Column('exploitable_crashes', sa.Integer(), default=0),
        sa.Column('coverage_edges', sa.Integer(), default=0),

        # Timestamps
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_sec', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ========================================================================
    # Android Crashes Table
    # ========================================================================
    op.create_table(
        'android_crashes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('crash_id', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('android_fuzz_campaigns.campaign_id', ondelete='CASCADE'), nullable=True, index=True),

        # Crash Details
        sa.Column('crash_type', sa.String(32), nullable=False),  # segfault, java_exception, anr, etc.
        sa.Column('source', sa.String(32), nullable=False),  # native, intent
        sa.Column('severity', sa.String(32), default='medium'),  # critical, high, medium, low
        sa.Column('component', sa.String(256), nullable=True),  # Library or component name
        sa.Column('function_name', sa.String(256), nullable=True),

        # Exception/Signal Info
        sa.Column('exception_class', sa.String(256), nullable=True),
        sa.Column('exception_message', sa.Text(), nullable=True),
        sa.Column('signal', sa.Integer(), nullable=True),
        sa.Column('address', sa.BigInteger(), nullable=True),

        # Stack Trace
        sa.Column('stack_trace', sa.Text(), nullable=True),
        sa.Column('register_state', postgresql.JSON(), nullable=True),

        # Input
        sa.Column('input_hash', sa.String(64), nullable=True),
        sa.Column('input_data', sa.LargeBinary(), nullable=True),
        sa.Column('intent_command', sa.Text(), nullable=True),

        # Analysis
        sa.Column('is_unique', sa.Boolean(), default=True),
        sa.Column('is_exploitable', sa.Boolean(), default=False),
        sa.Column('exploitability_reason', sa.Text(), nullable=True),
        sa.Column('analysis_json', postgresql.JSON(), nullable=True),

        # CWE/CVE
        sa.Column('cwe_ids', postgresql.ARRAY(sa.String(32)), nullable=True),
        sa.Column('cve_ids', postgresql.ARRAY(sa.String(32)), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ========================================================================
    # Android Native Fuzzing Sessions Table
    # ========================================================================
    op.create_table(
        'android_native_fuzz_sessions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('android_fuzz_campaigns.campaign_id', ondelete='SET NULL'), nullable=True),
        sa.Column('device_serial', sa.String(64), nullable=False),

        # Target
        sa.Column('library_name', sa.String(256), nullable=False),
        sa.Column('library_path', sa.String(512), nullable=True),
        sa.Column('target_function', sa.String(256), nullable=True),
        sa.Column('architecture', sa.String(32), nullable=True),

        # Configuration
        sa.Column('fuzz_mode', sa.String(32), default='frida'),  # frida, qemu, afl_frida
        sa.Column('config_json', postgresql.JSON(), nullable=True),

        # Status
        sa.Column('status', sa.String(32), default='pending'),
        sa.Column('error_message', sa.Text(), nullable=True),

        # Statistics
        sa.Column('executions', sa.Integer(), default=0),
        sa.Column('crashes', sa.Integer(), default=0),
        sa.Column('unique_crashes', sa.Integer(), default=0),
        sa.Column('timeouts', sa.Integer(), default=0),
        sa.Column('coverage_edges', sa.Integer(), default=0),
        sa.Column('coverage_blocks', sa.Integer(), default=0),
        sa.Column('exec_per_sec', sa.Float(), default=0.0),
        sa.Column('corpus_size', sa.Integer(), default=0),

        # Timestamps
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_sec', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ========================================================================
    # Android Intent Fuzzing Sessions Table
    # ========================================================================
    op.create_table(
        'android_intent_fuzz_sessions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('session_id', sa.String(64), unique=True, nullable=False, index=True),
        sa.Column('campaign_id', sa.String(64), sa.ForeignKey('android_fuzz_campaigns.campaign_id', ondelete='SET NULL'), nullable=True),
        sa.Column('device_serial', sa.String(64), nullable=False),

        # Target
        sa.Column('package_name', sa.String(256), nullable=False),
        sa.Column('target_component', sa.String(256), nullable=True),

        # Configuration
        sa.Column('fuzz_activities', sa.Boolean(), default=True),
        sa.Column('fuzz_services', sa.Boolean(), default=True),
        sa.Column('fuzz_receivers', sa.Boolean(), default=True),
        sa.Column('fuzz_providers', sa.Boolean(), default=True),
        sa.Column('mutation_rate', sa.Float(), default=0.3),
        sa.Column('config_json', postgresql.JSON(), nullable=True),

        # Status
        sa.Column('status', sa.String(32), default='pending'),
        sa.Column('error_message', sa.Text(), nullable=True),

        # Statistics
        sa.Column('intents_sent', sa.Integer(), default=0),
        sa.Column('crashes', sa.Integer(), default=0),
        sa.Column('unique_crashes', sa.Integer(), default=0),
        sa.Column('anrs', sa.Integer(), default=0),
        sa.Column('security_exceptions', sa.Integer(), default=0),
        sa.Column('components_tested', sa.Integer(), default=0),

        # Timestamps
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_sec', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ========================================================================
    # Android Emulator Snapshots Table
    # ========================================================================
    op.create_table(
        'android_emulator_snapshots',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('avd_name', sa.String(128), nullable=False, index=True),
        sa.Column('snapshot_name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('size_mb', sa.Integer(), nullable=True),
        sa.Column('is_valid', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),

        # Unique constraint on avd_name + snapshot_name
        sa.UniqueConstraint('avd_name', 'snapshot_name', name='uq_avd_snapshot')
    )

    # ========================================================================
    # Android Native Libraries Table (Analyzed)
    # ========================================================================
    op.create_table(
        'android_native_libraries',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('package_name', sa.String(256), nullable=False, index=True),
        sa.Column('library_name', sa.String(256), nullable=False),
        sa.Column('library_path', sa.String(512), nullable=True),
        sa.Column('architecture', sa.String(32), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=True),

        # Security Properties
        sa.Column('is_stripped', sa.Boolean(), default=True),
        sa.Column('is_pie', sa.Boolean(), default=False),
        sa.Column('has_stack_canary', sa.Boolean(), default=False),
        sa.Column('has_nx', sa.Boolean(), default=True),
        sa.Column('has_relro', sa.Boolean(), default=False),

        # Analysis Results
        sa.Column('exports_count', sa.Integer(), default=0),
        sa.Column('imports_count', sa.Integer(), default=0),
        sa.Column('dangerous_functions', postgresql.ARRAY(sa.String(64)), nullable=True),
        sa.Column('jni_functions', postgresql.ARRAY(sa.String(128)), nullable=True),
        sa.Column('analysis_json', postgresql.JSON(), nullable=True),

        # Hash for change detection
        sa.Column('file_hash', sa.String(64), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),

        # Unique constraint
        sa.UniqueConstraint('package_name', 'library_name', name='uq_package_library')
    )

    # ========================================================================
    # Android Exported Components Table
    # ========================================================================
    op.create_table(
        'android_exported_components',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('package_name', sa.String(256), nullable=False, index=True),
        sa.Column('component_name', sa.String(256), nullable=False),
        sa.Column('component_type', sa.String(32), nullable=False),  # activity, service, receiver, provider
        sa.Column('exported', sa.Boolean(), default=True),
        sa.Column('enabled', sa.Boolean(), default=True),
        sa.Column('permission', sa.String(256), nullable=True),
        sa.Column('process', sa.String(256), nullable=True),

        # Intent Filters
        sa.Column('intent_filters_json', postgresql.JSON(), nullable=True),

        # Analysis
        sa.Column('is_vulnerable', sa.Boolean(), default=False),
        sa.Column('vulnerability_notes', sa.Text(), nullable=True),
        sa.Column('fuzz_priority', sa.Integer(), default=0),  # Higher = more interesting

        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),

        # Unique constraint
        sa.UniqueConstraint('package_name', 'component_name', name='uq_package_component')
    )

    # ========================================================================
    # Create Indexes
    # ========================================================================
    op.create_index('ix_android_fuzz_campaigns_status', 'android_fuzz_campaigns', ['status'])
    op.create_index('ix_android_fuzz_campaigns_target', 'android_fuzz_campaigns', ['target_type'])
    op.create_index('ix_android_crashes_type', 'android_crashes', ['crash_type'])
    op.create_index('ix_android_crashes_severity', 'android_crashes', ['severity'])
    op.create_index('ix_android_crashes_exploitable', 'android_crashes', ['is_exploitable'])
    op.create_index('ix_android_native_fuzz_sessions_status', 'android_native_fuzz_sessions', ['status'])
    op.create_index('ix_android_intent_fuzz_sessions_status', 'android_intent_fuzz_sessions', ['status'])
    op.create_index('ix_android_native_libraries_package', 'android_native_libraries', ['package_name'])
    op.create_index('ix_android_exported_components_type', 'android_exported_components', ['component_type'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_android_exported_components_type')
    op.drop_index('ix_android_native_libraries_package')
    op.drop_index('ix_android_intent_fuzz_sessions_status')
    op.drop_index('ix_android_native_fuzz_sessions_status')
    op.drop_index('ix_android_crashes_exploitable')
    op.drop_index('ix_android_crashes_severity')
    op.drop_index('ix_android_crashes_type')
    op.drop_index('ix_android_fuzz_campaigns_target')
    op.drop_index('ix_android_fuzz_campaigns_status')

    # Drop tables
    op.drop_table('android_exported_components')
    op.drop_table('android_native_libraries')
    op.drop_table('android_emulator_snapshots')
    op.drop_table('android_intent_fuzz_sessions')
    op.drop_table('android_native_fuzz_sessions')
    op.drop_table('android_crashes')
    op.drop_table('android_fuzz_campaigns')
    op.drop_table('android_devices')
