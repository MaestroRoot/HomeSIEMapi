"""add cloudflare_gateway_configs

Revision ID: 8f3a2b1c9d4e
Revises: c2e7f1a9b04d
Create Date: 2026-08-06 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '8f3a2b1c9d4e'
down_revision = 'c2e7f1a9b04d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'cloudflare_gateway_configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('account_id', sa.String(length=64), nullable=False),
        sa.Column('api_token', sa.String(length=256), nullable=False),
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
    op.drop_index(op.f('ix_cloudflare_gateway_configs_organization_id'), table_name='cloudflare_gateway_configs')
    op.drop_table('cloudflare_gateway_configs')