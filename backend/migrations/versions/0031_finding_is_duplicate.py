"""Add is_duplicate column to findings for deduplication tracking

Revision ID: 0031_finding_is_duplicate
Revises: 0030_presence_kanban
Create Date: 2026-01-02

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0031_finding_is_duplicate'
down_revision = '0030_presence_kanban'
branch_labels = None
depends_on = None


def upgrade():
    # Add is_duplicate column with default False
    # This allows tracking of duplicate findings that were merged during deduplication
    op.add_column('findings', sa.Column('is_duplicate', sa.Boolean(), 
                                         nullable=False, server_default='false'))
    
    # Create index for efficient filtering
    op.create_index(op.f('ix_findings_is_duplicate'), 'findings', ['is_duplicate'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_findings_is_duplicate'), table_name='findings')
    op.drop_column('findings', 'is_duplicate')
