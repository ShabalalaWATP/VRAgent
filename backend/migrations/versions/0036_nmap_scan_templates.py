"""Add nmap_scan_templates table

Revision ID: 0036_nmap_scan_templates
Revises: 0035
Create Date: 2026-01-08
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0036_nmap_scan_templates'
down_revision = '0035'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'nmap_scan_templates',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_public', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('scan_type', sa.String(length=50), nullable=True),
        sa.Column('ports', sa.String(length=500), nullable=True),
        sa.Column('timing', sa.String(length=10), nullable=True),
        sa.Column('extra_args', sa.Text(), nullable=True),
        sa.Column('target_pattern', sa.String(length=200), nullable=True),
        sa.Column('use_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_nmap_scan_templates_id', 'nmap_scan_templates', ['id'], unique=False)
    op.create_index('ix_nmap_scan_templates_user_id', 'nmap_scan_templates', ['user_id'], unique=False)
    op.create_index('ix_nmap_scan_templates_is_public', 'nmap_scan_templates', ['is_public'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_nmap_scan_templates_is_public', table_name='nmap_scan_templates')
    op.drop_index('ix_nmap_scan_templates_user_id', table_name='nmap_scan_templates')
    op.drop_index('ix_nmap_scan_templates_id', table_name='nmap_scan_templates')
    op.drop_table('nmap_scan_templates')
