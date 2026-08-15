"""platform admin role

Revision ID: d5e6f7a8b9c0
Revises: 9c7e21a4d5b3
Create Date: 2026-08-15 12:00:00.000000

Inaongeza 'admin' kwenye enum `user_role` kwa ajili ya akaunti ya usimamizi wa
jukwaa zima (ADMIN_EMAIL). Alembic autogenerate haioni values mpya za enum,
hivyo tunaiongeza kwa mkono, kama ilivyofanyika kwa subscription_status.
"""
from collections.abc import Sequence

from alembic import op


revision: str = 'd5e6f7a8b9c0'
down_revision: str | None = '9c7e21a4d5b3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'admin'")


def downgrade() -> None:
    # Postgres haina DROP VALUE. Rows zilizotumia 'admin' lazima zishushwe
    # kwanza kwenye value nyingine, kisha type inajengwa upya bila 'admin'.
    op.execute("UPDATE users SET role = 'owner' WHERE role = 'admin'")
    op.execute("ALTER TYPE user_role RENAME TO user_role_old")
    op.execute(
        "CREATE TYPE user_role AS ENUM "
        "('owner', 'analyst', 'viewer')"
    )
    op.execute(
        "ALTER TABLE users ALTER COLUMN role TYPE user_role "
        "USING role::text::user_role"
    )
    op.execute("DROP TYPE user_role_old")
