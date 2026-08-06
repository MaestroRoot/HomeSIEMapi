"""business trial for new signups

Revision ID: f2963d39996f
Revises: 410874f3ed7d
Create Date: 2026-08-03 20:00:31.202507

Alembic autogenerate haioni values mpya zinazoongezwa kwenye enum iliyopo,
inaona columns pekee. Ndio maana `trialing` na `expired` zinaongezwa kwa mkono
hapa chini.
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = 'f2963d39996f'
down_revision: str | None = '410874f3ed7d'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_STATUSES = ('trialing', 'expired')


def upgrade() -> None:
    op.add_column(
        'subscriptions',
        sa.Column('trial_ends_at', sa.DateTime(timezone=True), nullable=True),
    )

    for value in NEW_STATUSES:
        op.execute(f"ALTER TYPE subscription_status ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # Rows zinazotumia values mpya lazima zishuke kwanza, vinginevyo
    # kuzifuta kunashindwa.
    op.execute(
        "UPDATE subscriptions SET status = 'cancelled' "
        "WHERE status IN ('trialing', 'expired')"
    )
    op.drop_column('subscriptions', 'trial_ends_at')

    # Postgres haina DROP VALUE, hivyo tunajenga type upya bila hizo mbili.
    op.execute("ALTER TYPE subscription_status RENAME TO subscription_status_old")
    op.execute(
        "CREATE TYPE subscription_status AS ENUM "
        "('active', 'pending', 'past_due', 'cancelled')"
    )
    op.execute(
        "ALTER TABLE subscriptions ALTER COLUMN status TYPE subscription_status "
        "USING status::text::subscription_status"
    )
    op.execute("DROP TYPE subscription_status_old")
