"""users organizations subscriptions payments

Revision ID: 0c2a4b1bb2d7
Revises:
Create Date: 2026-08-03 18:54:20.771840

Enum types zinaundwa MARA MOJA juu ya upgrade() kisha columns zinazitumia kwa
`create_type=False`. Bila hivyo `plan` (iko kwenye tables nne) ingejaribu
CREATE TYPE mara nne na migration ingekufa kwenye table ya pili.
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '0c2a4b1bb2d7'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


plan_enum = postgresql.ENUM(
    'Free', 'Home', 'Pro', 'Business', name='plan', create_type=False
)
user_role_enum = postgresql.ENUM(
    'owner', 'analyst', 'viewer', name='user_role', create_type=False
)
subscription_status_enum = postgresql.ENUM(
    'active', 'pending', 'past_due', 'cancelled', name='subscription_status', create_type=False
)
payment_method_enum = postgresql.ENUM(
    'mobile_money', 'bank_card', name='payment_method', create_type=False
)
payment_channel_enum = postgresql.ENUM(
    'yas_mix', 'mpesa', 'halopesa', 'airtel_money', 'card',
    name='payment_channel', create_type=False,
)
payment_status_enum = postgresql.ENUM(
    'pending', 'processing', 'succeeded', 'failed', 'cancelled',
    name='payment_status', create_type=False,
)

ALL_ENUMS = (
    plan_enum,
    user_role_enum,
    subscription_status_enum,
    payment_method_enum,
    payment_channel_enum,
    payment_status_enum,
)


def upgrade() -> None:
    bind = op.get_bind()
    for enum in ALL_ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        'organizations',
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('slug', sa.String(length=120), nullable=False),
        sa.Column('plan', plan_enum, nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    op.create_table(
        'subscriptions',
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('plan', plan_enum, nullable=False),
        sa.Column('status', subscription_status_enum, nullable=False),
        sa.Column('price_tzs', sa.Integer(), nullable=False),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('current_period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('auto_renew', sa.Boolean(), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_subscriptions_organization_id'), 'subscriptions', ['organization_id'], unique=True
    )

    op.create_table(
        'users',
        sa.Column('firebase_uid', sa.String(length=128), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('avatar_url', sa.String(length=512), nullable=True),
        sa.Column('role', user_role_enum, nullable=False),
        sa.Column('plan', plan_enum, nullable=False),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
        sa.Column('email_verified', sa.Boolean(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_firebase_uid'), 'users', ['firebase_uid'], unique=True)
    op.create_index(op.f('ix_users_organization_id'), 'users', ['organization_id'], unique=False)

    op.create_table(
        'payments',
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('subscription_id', sa.UUID(), nullable=True),
        sa.Column('initiated_by_id', sa.UUID(), nullable=True),
        sa.Column('plan', plan_enum, nullable=False),
        sa.Column('amount_tzs', sa.Integer(), nullable=False),
        sa.Column('currency', sa.String(length=3), nullable=False),
        sa.Column('method', payment_method_enum, nullable=False),
        sa.Column('channel', payment_channel_enum, nullable=False),
        sa.Column('status', payment_status_enum, nullable=False),
        sa.Column('msisdn', sa.String(length=20), nullable=True),
        sa.Column('card_last4', sa.String(length=4), nullable=True),
        sa.Column('card_brand', sa.String(length=20), nullable=True),
        sa.Column('reference', sa.String(length=64), nullable=False),
        sa.Column('provider_reference', sa.String(length=128), nullable=True),
        sa.Column('provider', sa.String(length=32), nullable=False),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('paid_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['initiated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_payments_organization_id'), 'payments', ['organization_id'], unique=False)
    op.create_index(op.f('ix_payments_provider_reference'), 'payments', ['provider_reference'], unique=False)
    op.create_index(op.f('ix_payments_reference'), 'payments', ['reference'], unique=True)
    op.create_index(op.f('ix_payments_status'), 'payments', ['status'], unique=False)
    op.create_index(op.f('ix_payments_subscription_id'), 'payments', ['subscription_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_payments_subscription_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_status'), table_name='payments')
    op.drop_index(op.f('ix_payments_reference'), table_name='payments')
    op.drop_index(op.f('ix_payments_provider_reference'), table_name='payments')
    op.drop_index(op.f('ix_payments_organization_id'), table_name='payments')
    op.drop_table('payments')

    op.drop_index(op.f('ix_users_organization_id'), table_name='users')
    op.drop_index(op.f('ix_users_firebase_uid'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

    op.drop_index(op.f('ix_subscriptions_organization_id'), table_name='subscriptions')
    op.drop_table('subscriptions')

    op.drop_index(op.f('ix_organizations_slug'), table_name='organizations')
    op.drop_table('organizations')

    bind = op.get_bind()
    for enum in reversed(ALL_ENUMS):
        enum.drop(bind, checkfirst=True)
