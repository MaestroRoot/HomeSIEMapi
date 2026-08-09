"""add paypal to payment_channel and payment_method enums

Revision ID: b1a2c3d4e5f6
Revises: 0c2a4b1bb2d7
Create Date: 2026-08-09 12:00:00.000000
"""
from collections.abc import Sequence

from alembic import op

revision: str = 'b1a2c3d4e5f6'
down_revision: str | None = '00f6861011dc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add 'paypal' to payment_channel enum
    op.execute("ALTER TYPE payment_channel ADD VALUE IF NOT EXISTS 'paypal'")
    # Add 'paypal' to payment_method enum
    op.execute("ALTER TYPE payment_method ADD VALUE IF NOT EXISTS 'paypal'")


def downgrade() -> None:
    # PostgreSQL enums cannot remove values; rebuild required.
    pass
