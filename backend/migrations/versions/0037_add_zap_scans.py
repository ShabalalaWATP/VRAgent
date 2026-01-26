"""add zap_scans table

Revision ID: 0037_add_zap_scans
Revises: 0036_nmap_scan_templates
Create Date: 2026-01-14

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0037_add_zap_scans'
down_revision = '0036_nmap_scan_templates'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'zap_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=255), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.Column('target_url', sa.Text(), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('urls_found', sa.Integer(), server_default='0'),
        sa.Column('alerts_high', sa.Integer(), server_default='0'),
        sa.Column('alerts_medium', sa.Integer(), server_default='0'),
        sa.Column('alerts_low', sa.Integer(), server_default='0'),
        sa.Column('alerts_info', sa.Integer(), server_default='0'),
        sa.Column('alerts_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('urls_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('stats', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    op.create_index('ix_zap_scans_id', 'zap_scans', ['id'])
    op.create_index('ix_zap_scans_session_id', 'zap_scans', ['session_id'])
    op.create_index('ix_zap_scans_user_id', 'zap_scans', ['user_id'])
    op.create_index('ix_zap_scans_project_id', 'zap_scans', ['project_id'])


def downgrade() -> None:
    op.drop_index('ix_zap_scans_project_id', table_name='zap_scans')
    op.drop_index('ix_zap_scans_user_id', table_name='zap_scans')
    op.drop_index('ix_zap_scans_session_id', table_name='zap_scans')
    op.drop_index('ix_zap_scans_id', table_name='zap_scans')
    op.drop_table('zap_scans')
