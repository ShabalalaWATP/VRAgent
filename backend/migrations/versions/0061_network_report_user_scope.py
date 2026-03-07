"""Add user ownership to network analysis reports.

Revision ID: 0061_network_report_user_scope
Revises: 0060_doc_translation_metrics
Create Date: 2026-03-07
"""

from typing import Set

from alembic import op
import sqlalchemy as sa


revision = "0061_network_report_user_scope"
down_revision = "0060_doc_translation_metrics"
branch_labels = None
depends_on = None


def _table_exists(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _existing_columns(table_name: str) -> Set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns(table_name)}


def _existing_indexes(table_name: str) -> Set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _existing_foreign_keys(table_name: str) -> Set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {fk["name"] for fk in inspector.get_foreign_keys(table_name) if fk.get("name")}


def upgrade():
    table_name = "network_analysis_reports"
    if not _table_exists(table_name):
        return

    columns = _existing_columns(table_name)
    indexes = _existing_indexes(table_name)
    foreign_keys = _existing_foreign_keys(table_name)

    if "user_id" not in columns:
        op.add_column(
            table_name,
            sa.Column("user_id", sa.Integer(), nullable=True),
        )

    if "ix_network_analysis_reports_user_id" not in indexes:
        op.create_index(
            "ix_network_analysis_reports_user_id",
            table_name,
            ["user_id"],
        )

    if "fk_network_analysis_reports_user_id" not in foreign_keys:
        op.create_foreign_key(
            "fk_network_analysis_reports_user_id",
            table_name,
            "users",
            ["user_id"],
            ["id"],
            ondelete="SET NULL",
        )

    if _table_exists("projects"):
        network_reports = sa.table(
            table_name,
            sa.column("user_id", sa.Integer()),
            sa.column("project_id", sa.Integer()),
        )
        projects = sa.table(
            "projects",
            sa.column("id", sa.Integer()),
            sa.column("owner_id", sa.Integer()),
        )

        update_stmt = network_reports.update().where(
            sa.and_(
                network_reports.c.user_id.is_(None),
                network_reports.c.project_id.isnot(None),
            )
        ).values(
            user_id=sa.select(projects.c.owner_id).where(
                projects.c.id == network_reports.c.project_id
            ).scalar_subquery()
        )
        op.get_bind().execute(update_stmt)


def downgrade():
    table_name = "network_analysis_reports"
    if not _table_exists(table_name):
        return

    columns = _existing_columns(table_name)
    indexes = _existing_indexes(table_name)
    foreign_keys = _existing_foreign_keys(table_name)

    if "fk_network_analysis_reports_user_id" in foreign_keys:
        op.drop_constraint(
            "fk_network_analysis_reports_user_id",
            table_name,
            type_="foreignkey",
        )

    if "ix_network_analysis_reports_user_id" in indexes:
        op.drop_index("ix_network_analysis_reports_user_id", table_name=table_name)

    if "user_id" in columns:
        op.drop_column(table_name, "user_id")
