"""Add color column to kanban_cards

Revision ID: 0034_kanban_card_color
Revises: 0033_whiteboard_collaboration
Create Date: 2026-01-04

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0034_kanban_card_color'
down_revision = '0033_whiteboard_collaboration'
branch_labels = None
depends_on = None


def upgrade():
    # Add color column to kanban_cards table
    op.add_column('kanban_cards', sa.Column('color', sa.String(), nullable=True))


def downgrade():
    # Remove color column from kanban_cards table
    op.drop_column('kanban_cards', 'color')
