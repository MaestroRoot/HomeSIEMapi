"""password reset codes and invitations

Revision ID: 410874f3ed7d
Revises: 0c2a4b1bb2d7
Create Date: 2026-08-03 19:35:08.619714

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '410874f3ed7d'
down_revision: str | None = '0c2a4b1bb2d7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# `user_role` iliundwa na migration ya kwanza, hivyo hapa tunaitumia tu.
# `invitation_status` ni mpya, tunaiunda mara moja juu ya upgrade().
user_role_enum = postgresql.ENUM(
    'owner', 'analyst', 'viewer', name='user_role', create_type=False
)
invitation_status_enum = postgresql.ENUM(
    'pending', 'accepted', 'revoked', 'expired', name='invitation_status', create_type=False
)


def upgrade() -> None:
    invitation_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table('password_reset_codes',
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('code_hash', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('reset_token_hash', sa.String(length=64), nullable=True),
    sa.Column('requested_ip', sa.String(length=64), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_password_reset_codes_email'), 'password_reset_codes', ['email'], unique=False)
    op.create_index(op.f('ix_password_reset_codes_reset_token_hash'), 'password_reset_codes', ['reset_token_hash'], unique=False)
    op.create_table('invitations',
    sa.Column('organization_id', sa.UUID(), nullable=False),
    sa.Column('invited_by_id', sa.UUID(), nullable=True),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('role', user_role_enum, nullable=False),
    sa.Column('status', invitation_status_enum, nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('email_sent', sa.Boolean(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['invited_by_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_invitations_email'), 'invitations', ['email'], unique=False)
    op.create_index(op.f('ix_invitations_organization_id'), 'invitations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_invitations_status'), 'invitations', ['status'], unique=False)
    op.create_index(op.f('ix_invitations_token_hash'), 'invitations', ['token_hash'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    op.drop_index(op.f('ix_invitations_token_hash'), table_name='invitations')
    op.drop_index(op.f('ix_invitations_status'), table_name='invitations')
    op.drop_index(op.f('ix_invitations_organization_id'), table_name='invitations')
    op.drop_index(op.f('ix_invitations_email'), table_name='invitations')
    op.drop_table('invitations')
    op.drop_index(op.f('ix_password_reset_codes_reset_token_hash'), table_name='password_reset_codes')
    op.drop_index(op.f('ix_password_reset_codes_email'), table_name='password_reset_codes')
    op.drop_table('password_reset_codes')

    # `user_role` inabaki, `users` bado inaitumia.
    invitation_status_enum.drop(op.get_bind(), checkfirst=True)
