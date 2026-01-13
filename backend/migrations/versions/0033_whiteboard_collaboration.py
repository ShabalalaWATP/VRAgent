"""Add whiteboard collaboration tables

Revision ID: 0033_whiteboard_collaboration
Revises: 0032_agentic_scan_reports
Create Date: 2026-01-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0033_whiteboard_collaboration'
down_revision = '0032_agentic_scan_reports'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create whiteboards table
    op.create_table(
        'whiteboards',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('canvas_width', sa.Integer(), server_default='3000', nullable=True),
        sa.Column('canvas_height', sa.Integer(), server_default='2000', nullable=True),
        sa.Column('background_color', sa.String(length=20), server_default='#1e1e2e', nullable=True),
        sa.Column('grid_enabled', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('is_locked', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('locked_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['locked_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_whiteboards_id', 'whiteboards', ['id'], unique=False)
    op.create_index('ix_whiteboards_project_id', 'whiteboards', ['project_id'], unique=False)

    # Create whiteboard_elements table
    op.create_table(
        'whiteboard_elements',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('whiteboard_id', sa.Integer(), nullable=False),
        sa.Column('element_id', sa.String(length=100), nullable=False),
        sa.Column('element_type', sa.String(length=50), nullable=False),
        sa.Column('x', sa.Float(), server_default='0', nullable=True),
        sa.Column('y', sa.Float(), server_default='0', nullable=True),
        sa.Column('width', sa.Float(), server_default='100', nullable=True),
        sa.Column('height', sa.Float(), server_default='100', nullable=True),
        sa.Column('rotation', sa.Float(), server_default='0', nullable=True),
        sa.Column('fill_color', sa.String(length=20), nullable=True),
        sa.Column('stroke_color', sa.String(length=20), server_default='#ffffff', nullable=True),
        sa.Column('stroke_width', sa.Float(), server_default='2', nullable=True),
        sa.Column('opacity', sa.Float(), server_default='1.0', nullable=True),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('font_size', sa.Integer(), server_default='16', nullable=True),
        sa.Column('font_family', sa.String(length=100), server_default='Inter', nullable=True),
        sa.Column('text_align', sa.String(length=20), server_default='left', nullable=True),
        sa.Column('image_url', sa.String(length=500), nullable=True),
        sa.Column('points', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('start_element_id', sa.String(length=100), nullable=True),
        sa.Column('end_element_id', sa.String(length=100), nullable=True),
        sa.Column('arrow_start', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('arrow_end', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('z_index', sa.Integer(), server_default='0', nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['whiteboard_id'], ['whiteboards.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_whiteboard_elements_id', 'whiteboard_elements', ['id'], unique=False)
    op.create_index('ix_whiteboard_elements_whiteboard_id', 'whiteboard_elements', ['whiteboard_id'], unique=False)
    op.create_index('ix_whiteboard_elements_element_id', 'whiteboard_elements', ['element_id'], unique=False)

    # Create annotations table
    op.create_table(
        'annotations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('original_image_url', sa.String(length=500), nullable=False),
        sa.Column('annotated_image_url', sa.String(length=500), nullable=True),
        sa.Column('annotations_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('note_id', sa.Integer(), nullable=True),
        sa.Column('whiteboard_id', sa.Integer(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['note_id'], ['project_notes.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['whiteboard_id'], ['whiteboards.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_annotations_id', 'annotations', ['id'], unique=False)
    op.create_index('ix_annotations_project_id', 'annotations', ['project_id'], unique=False)

    # Create mentions table
    op.create_table(
        'mentions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('mentioned_user_id', sa.Integer(), nullable=False),
        sa.Column('mentioned_by_id', sa.Integer(), nullable=False),
        sa.Column('note_id', sa.Integer(), nullable=True),
        sa.Column('whiteboard_element_id', sa.Integer(), nullable=True),
        sa.Column('message_id', sa.Integer(), nullable=True),
        sa.Column('context_text', sa.Text(), nullable=True),
        sa.Column('is_read', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['mentioned_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['mentioned_by_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['note_id'], ['project_notes.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['whiteboard_element_id'], ['whiteboard_elements.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['message_id'], ['messages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_mentions_id', 'mentions', ['id'], unique=False)
    op.create_index('ix_mentions_mentioned_user_id', 'mentions', ['mentioned_user_id'], unique=False)
    op.create_index('ix_mentions_note_id', 'mentions', ['note_id'], unique=False)

    # Create whiteboard_presence table
    op.create_table(
        'whiteboard_presence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('whiteboard_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('cursor_x', sa.Float(), nullable=True),
        sa.Column('cursor_y', sa.Float(), nullable=True),
        sa.Column('viewport_x', sa.Float(), server_default='0', nullable=True),
        sa.Column('viewport_y', sa.Float(), server_default='0', nullable=True),
        sa.Column('viewport_zoom', sa.Float(), server_default='1.0', nullable=True),
        sa.Column('selected_element_id', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('last_activity', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['whiteboard_id'], ['whiteboards.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('whiteboard_id', 'user_id', name='uq_whiteboard_user_presence')
    )
    op.create_index('ix_whiteboard_presence_id', 'whiteboard_presence', ['id'], unique=False)
    op.create_index('ix_whiteboard_presence_whiteboard_id', 'whiteboard_presence', ['whiteboard_id'], unique=False)
    op.create_index('ix_whiteboard_presence_user_id', 'whiteboard_presence', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_whiteboard_presence_user_id', table_name='whiteboard_presence')
    op.drop_index('ix_whiteboard_presence_whiteboard_id', table_name='whiteboard_presence')
    op.drop_index('ix_whiteboard_presence_id', table_name='whiteboard_presence')
    op.drop_table('whiteboard_presence')
    
    op.drop_index('ix_mentions_note_id', table_name='mentions')
    op.drop_index('ix_mentions_mentioned_user_id', table_name='mentions')
    op.drop_index('ix_mentions_id', table_name='mentions')
    op.drop_table('mentions')
    
    op.drop_index('ix_annotations_project_id', table_name='annotations')
    op.drop_index('ix_annotations_id', table_name='annotations')
    op.drop_table('annotations')
    
    op.drop_index('ix_whiteboard_elements_element_id', table_name='whiteboard_elements')
    op.drop_index('ix_whiteboard_elements_whiteboard_id', table_name='whiteboard_elements')
    op.drop_index('ix_whiteboard_elements_id', table_name='whiteboard_elements')
    op.drop_table('whiteboard_elements')
    
    op.drop_index('ix_whiteboards_project_id', table_name='whiteboards')
    op.drop_index('ix_whiteboards_id', table_name='whiteboards')
    op.drop_table('whiteboards')
