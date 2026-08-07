"""add_ueba_tables

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-08-07 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID

revision = "d2e3f4a5b6c7"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # user_baselines
    op.create_table(
        "user_baselines",
        sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", PGUUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("owner_name", sa.String(120), index=True, nullable=False),
        sa.Column("normal_hours", JSONB, nullable=False, server_default="{}"),
        sa.Column("normal_processes", JSONB, nullable=False, server_default="[]"),
        sa.Column("normal_domains", JSONB, nullable=False, server_default="[]"),
        sa.Column("avg_daily_bytes", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("avg_daily_connections", sa.Integer, nullable=False, server_default="0"),
        sa.Column("ready", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("last_refreshed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "owner_name", name="uq_baseline_org_owner"),
    )

    # user_anomalies
    op.create_table(
        "user_anomalies",
        sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", PGUUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("owner_name", sa.String(120), index=True, nullable=False),
        sa.Column("anomaly_type", sa.String(48), index=True, nullable=False),
        sa.Column("severity", sa.String(16), index=True, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("evidence", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(24), nullable=False, server_default="open", index=True),
        sa.Column("device_name", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # user_risk_scores
    op.create_table(
        "user_risk_scores",
        sa.Column("id", PGUUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", PGUUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("owner_name", sa.String(120), index=True, nullable=False),
        sa.Column("current_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("previous_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("trend", sa.String(8), nullable=False, server_default="stable"),
        sa.Column("open_anomalies", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_anomalies", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "owner_name", name="uq_risk_org_owner"),
    )


def downgrade() -> None:
    op.drop_table("user_risk_scores")
    op.drop_table("user_anomalies")
    op.drop_table("user_baselines")
