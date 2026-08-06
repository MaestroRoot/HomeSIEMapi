"""nextdns configs

Revision ID: c2e7f1a9b04d
Revises: 00f6861011dc
Create Date: 2026-08-06 12:00:00.000000

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = 'c2e7f1a9b04d'
down_revision: str | None = '00f6861011dc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'nextdns_configs',
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('profile_id', sa.String(length=32), nullable=False),
        sa.Column('api_key', sa.String(length=128), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status', sa.String(length=200), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', name='uq_nextdns_org'),
    )
    op.create_index(op.f('ix_nextdns_configs_organization_id'), 'nextdns_configs', ['organization_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_nextdns_configs_organization_id'), table_name='nextdns_configs')
    op.drop_table('nextdns_configs')
