"""add doh_subdomain to cloudflare_gateway_configs

Historical migration from the Cloudflare Gateway era. Kept only to preserve the
revision chain; the `cloudflare_gateway_configs` table no longer exists on fresh
databases, so this becomes a no-op there (the table is dropped by the later
`add_nextdns_configs` migration).

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-08-08 00:00:00.000000
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = 'e3f4a5b6c7d8'
down_revision: str | None = 'd2e3f4a5b6c7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if 'cloudflare_gateway_configs' in tables:
        op.add_column('cloudflare_gateway_configs', sa.Column('doh_subdomain', sa.String(length=128), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    tables = inspect(bind).get_table_names()
    if 'cloudflare_gateway_configs' in tables:
        op.drop_column('cloudflare_gateway_configs', 'doh_subdomain')
