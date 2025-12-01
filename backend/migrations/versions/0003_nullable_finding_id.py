"""Make finding_id nullable in exploit_scenarios for executive summaries

Revision ID: 0003
Revises: 0002
Create Date: 2025-11-30

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    # Make finding_id nullable to allow executive summary scenarios
    # that aren't tied to a specific finding
    op.alter_column('exploit_scenarios', 'finding_id',
                    existing_type=sa.INTEGER(),
                    nullable=True)


def downgrade():
    # First delete any rows with null finding_id
    op.execute("DELETE FROM exploit_scenarios WHERE finding_id IS NULL")
    # Then make it not nullable again
    op.alter_column('exploit_scenarios', 'finding_id',
                    existing_type=sa.INTEGER(),
                    nullable=False)
