"""Add manifest_visualization and obfuscation_analysis columns to reverse_engineering_reports

Revision ID: 0028_manifest_obf
Revises: 0027_apk_analysis_fields
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


# revision identifiers, used by Alembic.
revision: str = '0028_manifest_obf'
down_revision: Union[str, None] = '0027_apk_analysis_fields'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add manifest_visualization column
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('manifest_visualization', JSON, nullable=True)
    )
    
    # Add obfuscation_analysis column
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('obfuscation_analysis', JSON, nullable=True)
    )


def downgrade() -> None:
    # Remove obfuscation_analysis column
    op.drop_column('reverse_engineering_reports', 'obfuscation_analysis')
    
    # Remove manifest_visualization column
    op.drop_column('reverse_engineering_reports', 'manifest_visualization')
