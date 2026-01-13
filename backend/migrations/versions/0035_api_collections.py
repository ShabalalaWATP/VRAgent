"""API Collections - Postman-style organization

Revision ID: 0035
Revises: 0034
Create Date: 2026-01-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "0035"
down_revision = "0034_kanban_card_color"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # API Collections table
    op.create_table(
        "api_collections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("variables", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("pre_request_script", sa.Text(), nullable=True),
        sa.Column("test_script", sa.Text(), nullable=True),
        sa.Column("auth_type", sa.String(50), nullable=True),
        sa.Column("auth_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("headers", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("imported_from", sa.String(50), nullable=True),
        sa.Column("postman_id", sa.String(100), nullable=True),
        sa.Column("is_shared", sa.Boolean(), default=False),
        sa.Column("shared_with", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_collections_id", "api_collections", ["id"])
    op.create_index("ix_api_collections_user_id", "api_collections", ["user_id"])

    # API Folders table
    op.create_table(
        "api_folders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collection_id", sa.Integer(), nullable=False),
        sa.Column("parent_folder_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("auth_type", sa.String(50), nullable=True),
        sa.Column("auth_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("pre_request_script", sa.Text(), nullable=True),
        sa.Column("test_script", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["collection_id"], ["api_collections.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_folder_id"], ["api_folders.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_folders_id", "api_folders", ["id"])
    op.create_index("ix_api_folders_collection_id", "api_folders", ["collection_id"])
    op.create_index("ix_api_folders_parent_folder_id", "api_folders", ["parent_folder_id"])

    # API Requests table
    op.create_table(
        "api_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("collection_id", sa.Integer(), nullable=False),
        sa.Column("folder_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("method", sa.String(20), nullable=False, default="GET"),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("params", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("headers", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("body_type", sa.String(50), nullable=True),
        sa.Column("body_content", sa.Text(), nullable=True),
        sa.Column("body_form_data", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("graphql_query", sa.Text(), nullable=True),
        sa.Column("graphql_variables", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("auth_type", sa.String(50), nullable=True),
        sa.Column("auth_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("pre_request_script", sa.Text(), nullable=True),
        sa.Column("test_script", sa.Text(), nullable=True),
        sa.Column("timeout_ms", sa.Integer(), default=30000),
        sa.Column("follow_redirects", sa.Boolean(), default=True),
        sa.Column("saved_responses", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("sort_order", sa.Integer(), default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["collection_id"], ["api_collections.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["folder_id"], ["api_folders.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_requests_id", "api_requests", ["id"])
    op.create_index("ix_api_requests_collection_id", "api_requests", ["collection_id"])
    op.create_index("ix_api_requests_folder_id", "api_requests", ["folder_id"])

    # API Environments table
    op.create_table(
        "api_environments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("color", sa.String(20), nullable=True),
        sa.Column("variables", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("is_global", sa.Boolean(), default=False),
        sa.Column("is_active", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_environments_id", "api_environments", ["id"])
    op.create_index("ix_api_environments_user_id", "api_environments", ["user_id"])

    # API Request History table
    op.create_table(
        "api_request_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("collection_id", sa.Integer(), nullable=True),
        sa.Column("request_id", sa.Integer(), nullable=True),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("original_url", sa.Text(), nullable=True),
        sa.Column("headers", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("status_text", sa.String(100), nullable=True),
        sa.Column("response_headers", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("response_size_bytes", sa.Integer(), nullable=True),
        sa.Column("response_time_ms", sa.Float(), nullable=True),
        sa.Column("request_cookies", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("response_cookies", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("test_results", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("tests_passed", sa.Integer(), default=0),
        sa.Column("tests_failed", sa.Integer(), default=0),
        sa.Column("security_findings", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("environment_id", sa.Integer(), nullable=True),
        sa.Column("environment_name", sa.String(255), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["collection_id"], ["api_collections.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["request_id"], ["api_requests.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["environment_id"], ["api_environments.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_request_history_id", "api_request_history", ["id"])
    op.create_index("ix_api_request_history_user_id", "api_request_history", ["user_id"])
    op.create_index("ix_api_request_history_executed_at", "api_request_history", ["executed_at"])

    # API Global Variables table
    op.create_table(
        "api_global_variables",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("var_type", sa.String(20), default="default"),
        sa.Column("enabled", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "key", name="uq_user_global_var"),
    )
    op.create_index("ix_api_global_variables_id", "api_global_variables", ["id"])
    op.create_index("ix_api_global_variables_user_id", "api_global_variables", ["user_id"])

    # API Cookie Jars table
    op.create_table(
        "api_cookie_jars",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("cookies", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "domain", name="uq_user_cookie_domain"),
    )
    op.create_index("ix_api_cookie_jars_id", "api_cookie_jars", ["id"])
    op.create_index("ix_api_cookie_jars_user_id", "api_cookie_jars", ["user_id"])


def downgrade() -> None:
    op.drop_table("api_cookie_jars")
    op.drop_table("api_global_variables")
    op.drop_table("api_request_history")
    op.drop_table("api_environments")
    op.drop_table("api_requests")
    op.drop_table("api_folders")
    op.drop_table("api_collections")
