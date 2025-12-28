"""Add document analysis reports and report chat tables

Revision ID: 0026_doc_analysis_reports
Revises: 0025_project_files_docs
Create Date: 2024-12-23

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0026_doc_analysis_reports'
down_revision = '0025_project_files_docs'
branch_labels = None
depends_on = None


def upgrade():
    # Create document_analysis_reports table
    op.create_table(
        'document_analysis_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('custom_prompt', sa.Text(), nullable=True),
        sa.Column('combined_summary', sa.Text(), nullable=True),
        sa.Column('combined_key_points', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_document_analysis_reports_project_id', 'document_analysis_reports', ['project_id'])
    op.create_index('ix_document_analysis_reports_created_by', 'document_analysis_reports', ['created_by'])
    
    # Add report_id column to project_documents
    op.add_column('project_documents', 
        sa.Column('report_id', sa.Integer(), nullable=True)
    )
    op.create_foreign_key(
        'fk_project_documents_report_id',
        'project_documents', 'document_analysis_reports',
        ['report_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_index('ix_project_documents_report_id', 'project_documents', ['report_id'])
    
    # Create report_chat_messages table
    op.create_table(
        'report_chat_messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('report_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['report_id'], ['document_analysis_reports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_report_chat_messages_report_id', 'report_chat_messages', ['report_id'])
    op.create_index('ix_report_chat_messages_user_id', 'report_chat_messages', ['user_id'])


def downgrade():
    # Drop report_chat_messages
    op.drop_index('ix_report_chat_messages_user_id', 'report_chat_messages')
    op.drop_index('ix_report_chat_messages_report_id', 'report_chat_messages')
    op.drop_table('report_chat_messages')
    
    # Remove report_id from project_documents
    op.drop_index('ix_project_documents_report_id', 'project_documents')
    op.drop_constraint('fk_project_documents_report_id', 'project_documents', type_='foreignkey')
    op.drop_column('project_documents', 'report_id')
    
    # Drop document_analysis_reports
    op.drop_index('ix_document_analysis_reports_created_by', 'document_analysis_reports')
    op.drop_index('ix_document_analysis_reports_project_id', 'document_analysis_reports')
    op.drop_table('document_analysis_reports')
