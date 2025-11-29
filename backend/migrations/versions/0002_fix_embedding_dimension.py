"""fix embedding dimension to 768 for text-embedding-004

Revision ID: 0002
Revises: 0001
Create Date: 2025-11-29
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Change embedding column from 1536 to 768 dimensions
    # This requires dropping and recreating the column since pgvector
    # doesn't support ALTER COLUMN for dimension changes
    op.drop_column("code_chunks", "embedding")
    op.execute("ALTER TABLE code_chunks ADD COLUMN embedding vector(768)")
    
    # Add useful indexes
    op.create_index("ix_code_chunks_project_id", "code_chunks", ["project_id"])
    op.create_index("ix_dependencies_project_id", "dependencies", ["project_id"])
    op.create_index("ix_vulnerabilities_project_id", "vulnerabilities", ["project_id"])
    op.create_index("ix_findings_scan_run_id", "findings", ["scan_run_id"])
    op.create_index("ix_reports_project_id", "reports", ["project_id"])
    op.create_index("ix_exploit_scenarios_report_id", "exploit_scenarios", ["report_id"])


def downgrade() -> None:
    # Remove indexes
    op.drop_index("ix_exploit_scenarios_report_id", "exploit_scenarios")
    op.drop_index("ix_reports_project_id", "reports")
    op.drop_index("ix_findings_scan_run_id", "findings")
    op.drop_index("ix_vulnerabilities_project_id", "vulnerabilities")
    op.drop_index("ix_dependencies_project_id", "dependencies")
    op.drop_index("ix_code_chunks_project_id", "code_chunks")
    
    # Revert embedding column to 1536 dimensions
    op.drop_column("code_chunks", "embedding")
    op.execute("ALTER TABLE code_chunks ADD COLUMN embedding vector(1536)")
