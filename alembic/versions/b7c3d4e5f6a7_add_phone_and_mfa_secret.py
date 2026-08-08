"""Add phone and mfa_secret to users

Revision ID: b7c3d4e5f6a7
Revises: 8f3a2b1c9d4e
Create Date: 2026-08-07
"""

from alembic import op
import sqlalchemy as sa

revision = "b7c3d4e5f6a7"
down_revision = "00f6861011dc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("phone", sa.String(30), nullable=True))
    op.add_column("users", sa.Column("mfa_secret", sa.String(128), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "phone")
