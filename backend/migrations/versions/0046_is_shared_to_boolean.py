"""Convert is_shared from String to Boolean

Revision ID: 0046
Revises: 0045
Create Date: 2026-01-22

Converts the is_shared column in projects table from String ('true'/'false')
to proper Boolean type for type safety and consistency.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = '0046'
down_revision = '0045'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Step 1: Add a temporary boolean column
    op.add_column('projects', sa.Column('is_shared_bool', sa.Boolean(), nullable=True))

    # Step 2: Migrate data from string to boolean
    op.execute("""
        UPDATE projects
        SET is_shared_bool = CASE
            WHEN is_shared = 'true' THEN true
            ELSE false
        END
    """)

    # Step 3: Drop the old string column
    op.drop_column('projects', 'is_shared')

    # Step 4: Rename the new column to is_shared
    op.alter_column('projects', 'is_shared_bool', new_column_name='is_shared')

    # Step 5: Set not null constraint and default
    op.alter_column('projects', 'is_shared', nullable=False, server_default='false')


def downgrade() -> None:
    # Step 1: Add a temporary string column
    op.add_column('projects', sa.Column('is_shared_str', sa.String(), nullable=True))

    # Step 2: Migrate data from boolean to string
    op.execute("""
        UPDATE projects
        SET is_shared_str = CASE
            WHEN is_shared = true THEN 'true'
            ELSE 'false'
        END
    """)

    # Step 3: Drop the boolean column
    op.drop_column('projects', 'is_shared')

    # Step 4: Rename back to is_shared
    op.alter_column('projects', 'is_shared_str', new_column_name='is_shared')

    # Step 5: Set not null constraint and default
    op.alter_column('projects', 'is_shared', nullable=False, server_default='false')
