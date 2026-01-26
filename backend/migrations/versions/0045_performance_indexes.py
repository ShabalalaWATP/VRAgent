"""Performance indexes for Phase 2

Revision ID: 0045
Revises: 0044_mitm_analysis
Create Date: 2026-01-20

Adds comprehensive indexes for query performance optimization
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers
revision = '0045'
down_revision = '0044_mitm_analysis'
branch_labels = None
depends_on = None


def upgrade():
    """Add performance indexes"""

    # ========================================================================
    # SCANS TABLE INDEXES
    # ========================================================================

    # Composite index for user's scans by status
    op.create_index(
        'ix_scans_user_status_created',
        'scans',
        ['user_id', 'status', 'created_at'],
        unique=False
    )

    # Index for finding recent scans
    op.create_index(
        'ix_scans_created_at',
        'scans',
        ['created_at'],
        unique=False,
        postgresql_using='brin'  # Block Range Index for timestamp columns
    )

    # Index for scan type filtering
    op.create_index(
        'ix_scans_scan_type',
        'scans',
        ['scan_type'],
        unique=False
    )

    # Index for project scans
    op.create_index(
        'ix_scans_project_id',
        'scans',
        ['project_id'],
        unique=False
    )

    # ========================================================================
    # BINARY METADATA INDEXES
    # ========================================================================

    # Index for SHA256 lookups (most common query)
    op.create_index(
        'ix_binary_metadata_sha256',
        'binary_metadata',
        ['sha256'],
        unique=True
    )

    # Index for scan lookups
    op.create_index(
        'ix_binary_metadata_scan_id',
        'binary_metadata',
        ['scan_id'],
        unique=False
    )

    # Index for architecture filtering
    op.create_index(
        'ix_binary_metadata_architecture',
        'binary_metadata',
        ['architecture'],
        unique=False
    )

    # Index for finding packed binaries
    op.create_index(
        'ix_binary_metadata_is_packed',
        'binary_metadata',
        ['is_packed'],
        unique=False,
        postgresql_where=sa.text('is_packed = true')  # Partial index
    )

    # ========================================================================
    # FUZZING CAMPAIGNS INDEXES
    # ========================================================================

    # Index for user's campaigns
    op.create_index(
        'ix_fuzz_campaigns_user_id',
        'fuzz_campaigns',
        ['user_id'],
        unique=False
    )

    # Index for active campaigns
    op.create_index(
        'ix_fuzz_campaigns_status',
        'fuzz_campaigns',
        ['status'],
        unique=False
    )

    # Composite index for user's active campaigns
    op.create_index(
        'ix_fuzz_campaigns_user_status',
        'fuzz_campaigns',
        ['user_id', 'status'],
        unique=False
    )

    # Index for campaign ID lookups
    op.create_index(
        'ix_fuzz_campaigns_campaign_id',
        'fuzz_campaigns',
        ['campaign_id'],
        unique=True
    )

    # ========================================================================
    # FUZZING CRASHES INDEXES
    # ========================================================================

    # Index for campaign crashes
    op.create_index(
        'ix_fuzz_crashes_campaign_id',
        'fuzz_crashes',
        ['campaign_id'],
        unique=False
    )

    # Index for unique crashes
    op.create_index(
        'ix_fuzz_crashes_is_unique',
        'fuzz_crashes',
        ['is_unique'],
        unique=False,
        postgresql_where=sa.text('is_unique = true')  # Partial index
    )

    # Index for crash hash (deduplication)
    op.create_index(
        'ix_fuzz_crashes_crash_hash',
        'fuzz_crashes',
        ['crash_hash'],
        unique=False
    )

    # Index for exploitable crashes
    op.create_index(
        'ix_fuzz_crashes_exploitability',
        'fuzz_crashes',
        ['exploitability'],
        unique=False
    )

    # Composite index for campaign's unique crashes by severity
    op.create_index(
        'ix_fuzz_crashes_campaign_unique_severity',
        'fuzz_crashes',
        ['campaign_id', 'is_unique', 'severity'],
        unique=False
    )

    # ========================================================================
    # YARA MATCHES INDEXES
    # ========================================================================

    # Index for scan's YARA matches
    op.create_index(
        'ix_yara_matches_scan_id',
        'yara_matches',
        ['scan_id'],
        unique=False
    )

    # Index for rule name lookups
    op.create_index(
        'ix_yara_matches_rule_name',
        'yara_matches',
        ['rule_name'],
        unique=False
    )

    # Index for category filtering
    op.create_index(
        'ix_yara_matches_category',
        'yara_matches',
        ['category'],
        unique=False
    )

    # Index for high severity matches
    op.create_index(
        'ix_yara_matches_severity',
        'yara_matches',
        ['severity'],
        unique=False,
        postgresql_where=sa.text("severity IN ('high', 'critical')")  # Partial
    )

    # ========================================================================
    # BINARY FUNCTIONS INDEXES
    # ========================================================================

    # Index for binary's functions
    op.create_index(
        'ix_binary_functions_binary_id',
        'binary_functions',
        ['binary_id'],
        unique=False
    )

    # Index for address lookups
    op.create_index(
        'ix_binary_functions_address',
        'binary_functions',
        ['address'],
        unique=False
    )

    # Index for function name searches
    op.create_index(
        'ix_binary_functions_name',
        'binary_functions',
        ['name'],
        unique=False,
        postgresql_ops={'name': 'text_pattern_ops'}  # For LIKE queries
    )

    # Index for high-risk functions
    op.create_index(
        'ix_binary_functions_risk_score',
        'binary_functions',
        ['risk_score'],
        unique=False,
        postgresql_where=sa.text('risk_score > 7')  # Partial index
    )

    # ========================================================================
    # PROJECTS INDEXES
    # ========================================================================

    # Index for user's projects
    op.create_index(
        'ix_projects_user_id',
        'projects',
        ['user_id'],
        unique=False
    )

    # Index for project name searches
    op.create_index(
        'ix_projects_name',
        'projects',
        ['name'],
        unique=False,
        postgresql_ops={'name': 'text_pattern_ops'}
    )

    # Index for recent projects
    op.create_index(
        'ix_projects_updated_at',
        'projects',
        ['updated_at'],
        unique=False,
        postgresql_using='brin'
    )

    # ========================================================================
    # REPORTS INDEXES
    # ========================================================================

    # Index for project reports
    op.create_index(
        'ix_reports_project_id',
        'reports',
        ['project_id'],
        unique=False
    )

    # Index for recent reports
    op.create_index(
        'ix_reports_created_at',
        'reports',
        ['created_at'],
        unique=False,
        postgresql_using='brin'
    )

    # ========================================================================
    # FINDINGS INDEXES
    # ========================================================================

    # Index for scan findings
    op.create_index(
        'ix_findings_scan_id',
        'findings',
        ['scan_id'],
        unique=False
    )

    # Index for severity filtering
    op.create_index(
        'ix_findings_severity',
        'findings',
        ['severity'],
        unique=False
    )

    # Composite index for scan's findings by severity
    op.create_index(
        'ix_findings_scan_severity',
        'findings',
        ['scan_id', 'severity'],
        unique=False
    )

    # Full-text search index for finding descriptions
    op.execute("""
        CREATE INDEX ix_findings_description_fts
        ON findings
        USING GIN(to_tsvector('english', description))
    """)

    # ========================================================================
    # ANDROID APK INDEXES
    # ========================================================================

    # Index for scan lookups
    op.create_index(
        'ix_android_apks_scan_id',
        'android_apks',
        ['scan_id'],
        unique=False
    )

    # Index for package name lookups
    op.create_index(
        'ix_android_apks_package_name',
        'android_apks',
        ['package_name'],
        unique=False
    )

    # Index for SDK version filtering
    op.create_index(
        'ix_android_apks_target_sdk',
        'android_apks',
        ['target_sdk'],
        unique=False
    )

    # ========================================================================
    # USERS INDEXES
    # ========================================================================

    # Index for username lookups (authentication)
    op.create_index(
        'ix_users_username',
        'users',
        ['username'],
        unique=True
    )

    # Index for email lookups
    op.create_index(
        'ix_users_email',
        'users',
        ['email'],
        unique=True
    )

    # Index for active users
    op.create_index(
        'ix_users_is_active',
        'users',
        ['is_active'],
        unique=False,
        postgresql_where=sa.text('is_active = true')
    )

    # ========================================================================
    # ANALYZE TABLES
    # ========================================================================

    # Update table statistics for query planner
    op.execute("ANALYZE scans")
    op.execute("ANALYZE binary_metadata")
    op.execute("ANALYZE fuzz_campaigns")
    op.execute("ANALYZE fuzz_crashes")
    op.execute("ANALYZE yara_matches")
    op.execute("ANALYZE binary_functions")
    op.execute("ANALYZE projects")
    op.execute("ANALYZE reports")
    op.execute("ANALYZE findings")
    op.execute("ANALYZE android_apks")
    op.execute("ANALYZE users")

    print("✅ Performance indexes created successfully")


def downgrade():
    """Remove performance indexes"""

    # Scans
    op.drop_index('ix_scans_user_status_created', table_name='scans')
    op.drop_index('ix_scans_created_at', table_name='scans')
    op.drop_index('ix_scans_scan_type', table_name='scans')
    op.drop_index('ix_scans_project_id', table_name='scans')

    # Binary metadata
    op.drop_index('ix_binary_metadata_sha256', table_name='binary_metadata')
    op.drop_index('ix_binary_metadata_scan_id', table_name='binary_metadata')
    op.drop_index('ix_binary_metadata_architecture', table_name='binary_metadata')
    op.drop_index('ix_binary_metadata_is_packed', table_name='binary_metadata')

    # Fuzzing campaigns
    op.drop_index('ix_fuzz_campaigns_user_id', table_name='fuzz_campaigns')
    op.drop_index('ix_fuzz_campaigns_status', table_name='fuzz_campaigns')
    op.drop_index('ix_fuzz_campaigns_user_status', table_name='fuzz_campaigns')
    op.drop_index('ix_fuzz_campaigns_campaign_id', table_name='fuzz_campaigns')

    # Fuzzing crashes
    op.drop_index('ix_fuzz_crashes_campaign_id', table_name='fuzz_crashes')
    op.drop_index('ix_fuzz_crashes_is_unique', table_name='fuzz_crashes')
    op.drop_index('ix_fuzz_crashes_crash_hash', table_name='fuzz_crashes')
    op.drop_index('ix_fuzz_crashes_exploitability', table_name='fuzz_crashes')
    op.drop_index('ix_fuzz_crashes_campaign_unique_severity', table_name='fuzz_crashes')

    # YARA matches
    op.drop_index('ix_yara_matches_scan_id', table_name='yara_matches')
    op.drop_index('ix_yara_matches_rule_name', table_name='yara_matches')
    op.drop_index('ix_yara_matches_category', table_name='yara_matches')
    op.drop_index('ix_yara_matches_severity', table_name='yara_matches')

    # Binary functions
    op.drop_index('ix_binary_functions_binary_id', table_name='binary_functions')
    op.drop_index('ix_binary_functions_address', table_name='binary_functions')
    op.drop_index('ix_binary_functions_name', table_name='binary_functions')
    op.drop_index('ix_binary_functions_risk_score', table_name='binary_functions')

    # Projects
    op.drop_index('ix_projects_user_id', table_name='projects')
    op.drop_index('ix_projects_name', table_name='projects')
    op.drop_index('ix_projects_updated_at', table_name='projects')

    # Reports
    op.drop_index('ix_reports_project_id', table_name='reports')
    op.drop_index('ix_reports_created_at', table_name='reports')

    # Findings
    op.drop_index('ix_findings_scan_id', table_name='findings')
    op.drop_index('ix_findings_severity', table_name='findings')
    op.drop_index('ix_findings_scan_severity', table_name='findings')
    op.execute("DROP INDEX IF EXISTS ix_findings_description_fts")

    # Android APKs
    op.drop_index('ix_android_apks_scan_id', table_name='android_apks')
    op.drop_index('ix_android_apks_package_name', table_name='android_apks')
    op.drop_index('ix_android_apks_target_sdk', table_name='android_apks')

    # Users
    op.drop_index('ix_users_username', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_is_active', table_name='users')

    print("✅ Performance indexes removed")
