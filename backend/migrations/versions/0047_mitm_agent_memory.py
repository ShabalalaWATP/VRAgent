"""Add MITM Agent Memory tables for cross-session learning

Revision ID: 0047_mitm_agent_memory
Revises: 0046_is_shared_to_boolean
Create Date: 2026-01-23

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0047_mitm_agent_memory'
down_revision = '0046'
branch_labels = None
depends_on = None


def upgrade():
    # Create MITM Agent Memories table
    op.create_table(
        'mitm_agent_memories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('memory_id', sa.String(36), nullable=False),
        sa.Column('tool_id', sa.String(64), nullable=False),
        sa.Column('target_host', sa.String(255), nullable=False),
        sa.Column('target_type', sa.String(64), nullable=True),
        sa.Column('attack_surface_snapshot', sa.JSON(), nullable=True),
        sa.Column('reasoning_chain_id', sa.String(36), nullable=True),
        sa.Column('reasoning_steps', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Float(), default=0.0),
        sa.Column('attack_succeeded', sa.Boolean(), default=False),
        sa.Column('credentials_captured', sa.Integer(), default=0),
        sa.Column('tokens_captured', sa.Integer(), default=0),
        sa.Column('sessions_hijacked', sa.Integer(), default=0),
        sa.Column('findings_generated', sa.Integer(), default=0),
        sa.Column('effectiveness_score', sa.Float(), default=0.0),
        sa.Column('phase', sa.String(32), nullable=True),
        sa.Column('chain_triggered', sa.String(64), nullable=True),
        sa.Column('execution_time_ms', sa.Float(), default=0.0),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mitm_agent_memories_id'), 'mitm_agent_memories', ['id'], unique=False)
    op.create_index(op.f('ix_mitm_agent_memories_memory_id'), 'mitm_agent_memories', ['memory_id'], unique=True)
    op.create_index(op.f('ix_mitm_agent_memories_tool_id'), 'mitm_agent_memories', ['tool_id'], unique=False)
    op.create_index(op.f('ix_mitm_agent_memories_target_host'), 'mitm_agent_memories', ['target_host'], unique=False)
    op.create_index('ix_mitm_agent_memories_target_tool', 'mitm_agent_memories', ['target_host', 'tool_id'], unique=False)
    op.create_index('ix_mitm_agent_memories_created', 'mitm_agent_memories', ['created_at'], unique=False)

    # Create MITM Tool Performance Stats table
    op.create_table(
        'mitm_tool_performance',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('tool_id', sa.String(64), nullable=False),
        sa.Column('target_type', sa.String(64), nullable=False),
        sa.Column('successes', sa.Integer(), default=0),
        sa.Column('failures', sa.Integer(), default=0),
        sa.Column('total_executions', sa.Integer(), default=0),
        sa.Column('total_findings', sa.Integer(), default=0),
        sa.Column('total_credentials', sa.Integer(), default=0),
        sa.Column('effectiveness_history', sa.JSON(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mitm_tool_performance_id'), 'mitm_tool_performance', ['id'], unique=False)
    op.create_index(op.f('ix_mitm_tool_performance_tool_id'), 'mitm_tool_performance', ['tool_id'], unique=False)
    op.create_index(op.f('ix_mitm_tool_performance_target_type'), 'mitm_tool_performance', ['target_type'], unique=False)
    op.create_index('ix_mitm_tool_performance_tool_target', 'mitm_tool_performance', ['tool_id', 'target_type'], unique=True)


def downgrade():
    # Drop MITM Tool Performance Stats table
    op.drop_index('ix_mitm_tool_performance_tool_target', table_name='mitm_tool_performance')
    op.drop_index(op.f('ix_mitm_tool_performance_target_type'), table_name='mitm_tool_performance')
    op.drop_index(op.f('ix_mitm_tool_performance_tool_id'), table_name='mitm_tool_performance')
    op.drop_index(op.f('ix_mitm_tool_performance_id'), table_name='mitm_tool_performance')
    op.drop_table('mitm_tool_performance')

    # Drop MITM Agent Memories table
    op.drop_index('ix_mitm_agent_memories_created', table_name='mitm_agent_memories')
    op.drop_index('ix_mitm_agent_memories_target_tool', table_name='mitm_agent_memories')
    op.drop_index(op.f('ix_mitm_agent_memories_target_host'), table_name='mitm_agent_memories')
    op.drop_index(op.f('ix_mitm_agent_memories_tool_id'), table_name='mitm_agent_memories')
    op.drop_index(op.f('ix_mitm_agent_memories_memory_id'), table_name='mitm_agent_memories')
    op.drop_index(op.f('ix_mitm_agent_memories_id'), table_name='mitm_agent_memories')
    op.drop_table('mitm_agent_memories')
