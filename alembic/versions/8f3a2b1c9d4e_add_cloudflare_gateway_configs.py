"""add cloudflare_gateway_configs (replaces nextdns_configs)

Revision ID: 8f3a2b1c9d4e
Revises: 6baa2929d182
Create Date: 2026-08-06 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = '8f3a2b1c9d4e'
down_revision = '6baa2929d182'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Get inspector to check existing tables
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    # Drop old nextdns_configs table if it exists (from deleted migration)
    if 'nextdns_configs' in tables:
        op.drop_index(op.f('ix_nextdns_configs_organization_id'), table_name='nextdns_configs')
        op.drop_table('nextdns_configs')

    # Create cloudflare_gateway_configs table
    op.create_table(
        'cloudflare_gateway_configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('location_id', sa.String(length=64), nullable=True),
        sa.Column('location_name', sa.String(length=128), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status', sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', name='uq_cloudflare_gateway_org')
    )
    op.create_index(op.f('ix_cloudflare_gateway_configs_organization_id'), 'cloudflare_gateway_configs', ['organization_id'], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    if 'cloudflare_gateway_configs' in tables:
        op.drop_index(op.f('ix_cloudflare_gateway_configs_organization_id'), table_name='cloudflare_gateway_configs')
        op.drop_table('cloudflare_gateway_configs')

    # Note: We don't recreate nextdns_configs on downgrade since that migration is gone