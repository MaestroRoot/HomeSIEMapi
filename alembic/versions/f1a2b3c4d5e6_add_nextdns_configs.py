"""add nextdns_configs (replaces cloudflare_gateway_configs)

Revision ID: f1a2b3c4d5e6
Revises: e3f4a5b6c7d8
Create Date: 2026-08-08 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "f1a2b3c4d5e6"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    # Drop old Cloudflare Gateway table (only if it exists — e.g. on a DB that
    # ran the previous cloudflare chain; fresh DBs never create it).
    if "cloudflare_gateway_configs" in tables:
        op.drop_index(
            op.f("ix_cloudflare_gateway_configs_organization_id"),
            table_name="cloudflare_gateway_configs",
        )
        op.drop_table("cloudflare_gateway_configs")

    # Create nextdns_configs
    op.create_table(
        "nextdns_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("profile_id", sa.String(length=32), nullable=True),
        sa.Column("profile_name", sa.String(length=120), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="uq_nextdns_configs_org"),
    )
    op.create_index(
        op.f("ix_nextdns_configs_organization_id"),
        "nextdns_configs",
        ["organization_id"],
        unique=False,
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    if "nextdns_configs" in tables:
        op.drop_index(op.f("ix_nextdns_configs_organization_id"), table_name="nextdns_configs")
        op.drop_table("nextdns_configs")
