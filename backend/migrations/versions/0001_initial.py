"""initial tables

Revision ID: 0001
Revises:
Create Date: 2025-11-28
"""

from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(), nullable=True, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("git_url", sa.String(), nullable=True),
        sa.Column("upload_path", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
    )

    op.create_table(
        "code_chunks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("code", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("embedding", Vector(1536)),
    )

    op.create_table(
        "dependencies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("ecosystem", sa.String(), nullable=True),
        sa.Column("manifest_path", sa.String(), nullable=True),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("dependency_id", sa.Integer(), sa.ForeignKey("dependencies.id"), nullable=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
    )

    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id")),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("linked_vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=True),
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id")),
        sa.Column("scan_run_id", sa.Integer(), sa.ForeignKey("scan_runs.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("overall_risk_score", sa.Float(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=True),
    )

    op.create_table(
        "exploit_scenarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("report_id", sa.Integer(), sa.ForeignKey("reports.id")),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("narrative", sa.Text(), nullable=True),
        sa.Column("preconditions", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("poc_outline", sa.Text(), nullable=True),
        sa.Column("mitigation_notes", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("exploit_scenarios")
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("scan_runs")
    op.drop_table("vulnerabilities")
    op.drop_table("dependencies")
    op.drop_table("code_chunks")
    op.drop_table("projects")
    op.drop_table("users")
