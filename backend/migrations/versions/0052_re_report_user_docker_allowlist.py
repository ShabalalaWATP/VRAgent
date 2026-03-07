"""Add RE report user_id and per-project Docker allowlist

Revision ID: 0052_re_report_user_docker_allowlist
Revises: 0051_doc_translations
Create Date: 2026-01-30

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0052_re_report_user_docker_allowlist'
down_revision = '0051_doc_translations'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'reverse_engineering_reports',
        sa.Column('user_id', sa.Integer(), nullable=True)
    )
    op.create_index('ix_reverse_engineering_reports_user_id', 'reverse_engineering_reports', ['user_id'])
    op.create_foreign_key(
        'fk_reverse_engineering_reports_user_id',
        'reverse_engineering_reports',
        'users',
        ['user_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # Backfill user_id for reports tied to projects (use project owner)
    conn = op.get_bind()
    if conn.dialect.name == 'sqlite':
        conn.execute(sa.text("""
            UPDATE reverse_engineering_reports
            SET user_id = (
                SELECT owner_id FROM projects WHERE projects.id = reverse_engineering_reports.project_id
            )
            WHERE user_id IS NULL AND project_id IS NOT NULL
        """))
    else:
        op.execute("""
            UPDATE reverse_engineering_reports r
            SET user_id = p.owner_id
            FROM projects p
            WHERE r.user_id IS NULL AND r.project_id IS NOT NULL AND p.id = r.project_id
        """)

    op.create_table(
        'project_docker_images',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('image_name', sa.String(), nullable=False),
        sa.Column('added_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', 'image_name', name='uq_project_docker_image'),
    )
    op.create_index('ix_project_docker_images_project_id', 'project_docker_images', ['project_id'])
    op.create_index('ix_project_docker_images_image_name', 'project_docker_images', ['image_name'])
    op.create_index('ix_project_docker_images_added_by', 'project_docker_images', ['added_by'])


def downgrade():
    op.drop_index('ix_project_docker_images_added_by', 'project_docker_images')
    op.drop_index('ix_project_docker_images_image_name', 'project_docker_images')
    op.drop_index('ix_project_docker_images_project_id', 'project_docker_images')
    op.drop_table('project_docker_images')

    op.drop_constraint('fk_reverse_engineering_reports_user_id', 'reverse_engineering_reports', type_='foreignkey')
    op.drop_index('ix_reverse_engineering_reports_user_id', 'reverse_engineering_reports')
    op.drop_column('reverse_engineering_reports', 'user_id')
