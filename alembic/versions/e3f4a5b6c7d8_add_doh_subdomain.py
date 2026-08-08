"""add doh_subdomain to cloudflare_gateway_configs

Fixes Cloudflare Gateway: the DoH hostname must be built from Cloudflare's
`doh_subdomain` (e.g. `riwodrr2bo.dns.cloudflare-gateway.com`), and the DNS
logs poller must use the location UUID (not the subdomain) as `location_id`.

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-08-08 00:00:00.000000
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e3f4a5b6c7d8'
down_revision: str | None = 'd2e3f4a5b6c7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('cloudflare_gateway_configs', sa.Column('doh_subdomain', sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column('cloudflare_gateway_configs', 'doh_subdomain')
