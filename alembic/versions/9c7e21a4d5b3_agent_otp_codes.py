"""agent otp codes for desktop agent linking

Revision ID: 9c7e21a4d5b3
Revises: f2963d39996f
Create Date: 2026-08-15 10:00:00.000000

OTP ya kuunganisha HomeSIEM Agent desktop app kwa akaunti ya email. Code
yenyewe haihifadhiwi — SHA-256 pekee, sawa na `password_reset_codes`.
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = '9c7e21a4d5b3'
down_revision: str | None = 'ab12cd34ef56'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('agent_otp_codes',
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('code_hash', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('requested_ip', sa.String(length=64), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agent_otp_codes_email'), 'agent_otp_codes', ['email'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_agent_otp_codes_email'), table_name='agent_otp_codes')
    op.drop_table('agent_otp_codes')
