"""create dashboards and dashboard_widgets tables

Revision ID: c2d3e4f5a6b7
Revises: b1a2c3d4e5f6
Create Date: 2026-08-09 12:00:00.000000
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'c2d3e4f5a6b7'
down_revision: str | None = 'b1a2c3d4e5f6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'dashboards',
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('created_by_id', sa.UUID(), nullable=True),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('template', sa.String(length=32), nullable=True),
        sa.Column('visibility', sa.String(length=16), nullable=False, server_default='org'),
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dashboards_organization_id', 'dashboards', ['organization_id'])

    op.create_table(
        'dashboard_widgets',
        sa.Column('dashboard_id', sa.UUID(), nullable=False),
        sa.Column('widget_type', sa.String(length=24), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('query', sa.Text(), nullable=True),
        sa.Column('config', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('position', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('sort_order', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_visible', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['dashboard_id'], ['dashboards.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dashboard_widgets_dashboard_id', 'dashboard_widgets', ['dashboard_id'])


def downgrade() -> None:
    op.drop_index('ix_dashboard_widgets_dashboard_id')
    op.drop_table('dashboard_widgets')
    op.drop_index('ix_dashboards_organization_id')
    op.drop_table('dashboards')
