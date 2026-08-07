"""add_device_owner_name

Revision ID: c1d2e3f4a5b6
Revises: b7c3d4e5f6a7
Create Date: 2026-08-07 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "c1d2e3f4a5b6"
down_revision = "b7c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("owner_name", sa.String(120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices", "owner_name")
