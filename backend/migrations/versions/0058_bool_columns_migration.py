"""Convert boolean string columns to proper Boolean type.

Revision ID: 0058
Revises: 0057_vulnerability_aliases
"""
from alembic import op
import sqlalchemy as sa

revision = '0058'
down_revision = '0057_vulnerability_aliases'
branch_labels = None
depends_on = None


def upgrade():
    # For each column: add temp bool column, copy data, drop old, rename new
    bool_columns = [
        ('conversations', 'is_group'),
        ('conversation_participants', 'is_muted'),
        ('messages', 'is_edited'),
        ('messages', 'is_deleted'),
        ('polls', 'is_anonymous'),
        ('polls', 'allow_add_options'),
        ('polls', 'is_closed'),
    ]

    for table, column in bool_columns:
        # Add temporary boolean column
        op.add_column(table, sa.Column(f'{column}_bool', sa.Boolean(), nullable=True))

        # Copy data: convert string to boolean
        op.execute(f"""
            UPDATE {table}
            SET {column}_bool = CASE
                WHEN LOWER({column}) = 'true' THEN true
                ELSE false
            END
        """)

        # Drop old string column
        op.drop_column(table, column)

        # Rename new column
        op.alter_column(table, f'{column}_bool', new_column_name=column, nullable=False, server_default=sa.text('false'))


def downgrade():
    bool_columns = [
        ('conversations', 'is_group'),
        ('conversation_participants', 'is_muted'),
        ('messages', 'is_edited'),
        ('messages', 'is_deleted'),
        ('polls', 'is_anonymous'),
        ('polls', 'allow_add_options'),
        ('polls', 'is_closed'),
    ]

    for table, column in bool_columns:
        op.add_column(table, sa.Column(f'{column}_str', sa.String(), nullable=True))
        op.execute(f"""
            UPDATE {table}
            SET {column}_str = CASE
                WHEN {column} = true THEN 'true'
                ELSE 'false'
            END
        """)
        op.drop_column(table, column)
        op.alter_column(table, f'{column}_str', new_column_name=column, nullable=False, server_default='false')
