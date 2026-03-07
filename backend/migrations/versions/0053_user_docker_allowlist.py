"""Add per-user Docker allowlist

Revision ID: 0053_user_docker_allowlist
Revises: 0052_re_report_user_docker_allowlist
Create Date: 2026-01-30

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0053_user_docker_allowlist'
down_revision = '0052_re_report_user_docker_allowlist'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user_docker_images',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('image_name', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'image_name', name='uq_user_docker_image'),
    )
    op.create_index('ix_user_docker_images_user_id', 'user_docker_images', ['user_id'])
    op.create_index('ix_user_docker_images_image_name', 'user_docker_images', ['image_name'])


def downgrade():
    op.drop_index('ix_user_docker_images_image_name', 'user_docker_images')
    op.drop_index('ix_user_docker_images_user_id', 'user_docker_images')
    op.drop_table('user_docker_images')
