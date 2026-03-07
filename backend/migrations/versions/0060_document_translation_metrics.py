"""Add missing document translation metrics columns.

Revision ID: 0060_doc_translation_metrics
Revises: 0059
Create Date: 2026-02-25
"""

from alembic import op
import sqlalchemy as sa
from typing import Set


revision = "0060_doc_translation_metrics"
down_revision = "0059"
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


def upgrade():
    table_name = "document_translations"
    if not _table_exists(table_name):
        return

    existing = _existing_columns(table_name)

    if "translate_images" not in existing:
        op.add_column(
            table_name,
            sa.Column("translate_images", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if "image_text_regions_translated" not in existing:
        op.add_column(table_name, sa.Column("image_text_regions_translated", sa.Integer(), nullable=True))
    if "headers_footers_skipped" not in existing:
        op.add_column(table_name, sa.Column("headers_footers_skipped", sa.Integer(), nullable=True))
    if "code_blocks_skipped" not in existing:
        op.add_column(table_name, sa.Column("code_blocks_skipped", sa.Integer(), nullable=True))
    if "links_preserved" not in existing:
        op.add_column(table_name, sa.Column("links_preserved", sa.Integer(), nullable=True))
    if "multi_column_pages" not in existing:
        op.add_column(table_name, sa.Column("multi_column_pages", sa.Integer(), nullable=True))
    if "quality_score" not in existing:
        op.add_column(table_name, sa.Column("quality_score", sa.Float(), nullable=True))
    if "exact_fonts_used" not in existing:
        op.add_column(table_name, sa.Column("exact_fonts_used", sa.Integer(), nullable=True))
    if "tables_stitched" not in existing:
        op.add_column(table_name, sa.Column("tables_stitched", sa.Integer(), nullable=True))


def downgrade():
    table_name = "document_translations"
    if not _table_exists(table_name):
        return

    existing = _existing_columns(table_name)

    for col in [
        "tables_stitched",
        "exact_fonts_used",
        "quality_score",
        "multi_column_pages",
        "links_preserved",
        "code_blocks_skipped",
        "headers_footers_skipped",
        "image_text_regions_translated",
        "translate_images",
    ]:
        if col in existing:
            op.drop_column(table_name, col)
