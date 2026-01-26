"""Add document translations and analysis depth

Revision ID: 0051_doc_translations
Revises: 0050_fuzzing_campaign_reports
Create Date: 2026-01-25

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0051_doc_translations'
down_revision = '0050_fuzzing_campaign_reports'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'document_analysis_reports',
        sa.Column('analysis_depth', sa.String(), nullable=False, server_default='deep')
    )

    op.create_table(
        'document_translations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), nullable=True),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('original_filename', sa.String(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('mime_type', sa.String(), nullable=True),
        sa.Column('output_filename', sa.String(), nullable=True),
        sa.Column('output_path', sa.String(), nullable=True),
        sa.Column('output_url', sa.String(), nullable=True),
        sa.Column('source_language', sa.String(), nullable=True),
        sa.Column('target_language', sa.String(), nullable=False, server_default='English'),
        sa.Column('ocr_languages', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ocr_used', sa.Boolean(), nullable=True, server_default=sa.text('false')),
        sa.Column('page_count', sa.Integer(), nullable=True),
        sa.Column('chars_extracted', sa.Integer(), nullable=True),
        sa.Column('chars_translated', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_document_translations_project_id', 'document_translations', ['project_id'])
    op.create_index('ix_document_translations_uploaded_by', 'document_translations', ['uploaded_by'])


def downgrade():
    op.drop_index('ix_document_translations_uploaded_by', 'document_translations')
    op.drop_index('ix_document_translations_project_id', 'document_translations')
    op.drop_table('document_translations')

    op.drop_column('document_analysis_reports', 'analysis_depth')
