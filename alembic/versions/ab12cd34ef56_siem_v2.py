"""SIEM v2: normalized events, data sources, alerts, response actions.

- security_events: ongeza normalized fields (event_type, account, process_name,
  command_line, file_path, parent_process, source, raw).
- detection_rules: ongeza MITRE mapping + correlation (window_seconds, group_by,
  threshold) + description.
- incidents: ongeza timeline, entities, alert_ids.
- tables mpya: data_sources, alerts, response_actions.

Revision ID: ab12cd34ef56
Revises: c2d3e4f5a6b7
Create Date: 2026-08-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "ab12cd34ef56"
down_revision: str | None = "c2d3e4f5a6b7"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    # --- security_events: normalized fields --------------------------------
    op.add_column(
        "security_events",
        sa.Column("event_type", sa.String(length=24), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("account", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("process_name", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("command_line", sa.Text(), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("file_path", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("parent_process", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("source", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "security_events",
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_account", "security_events", ["account"])
    op.create_index("ix_security_events_source", "security_events", ["source"])

    # --- detection_rules: MITRE + correlation + description -----------------
    op.add_column(
        "detection_rules",
        sa.Column("description", sa.Text(), server_default="", nullable=False),
    )
    op.add_column(
        "detection_rules",
        sa.Column("mitre_tactic", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "detection_rules",
        sa.Column("mitre_technique", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "detection_rules",
        sa.Column("window_seconds", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "detection_rules",
        sa.Column("group_by", sa.String(length=32), server_default="", nullable=False),
    )
    op.add_column(
        "detection_rules",
        sa.Column("threshold", sa.Integer(), server_default="1", nullable=False),
    )

    # --- incidents: case workspace columns ----------------------------------
    op.add_column(
        "incidents",
        sa.Column("timeline", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("entities", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column("alert_ids", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
    )

    # --- data_sources -------------------------------------------------------
    op.create_table(
        "data_sources",
        sa.Column(
            "organization_id",
            sa.UUID(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("type", sa.String(length=24), server_default="sensor", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=400), nullable=True),
        sa.Column("events_total", sa.BigInteger(), server_default="0", nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_data_sources_organization_id", "data_sources", ["organization_id"])
    op.create_index("ix_data_sources_name", "data_sources", ["name"])

    # --- alerts -------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column(
            "organization_id",
            sa.UUID(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            sa.UUID(),
            sa.ForeignKey("detection_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            sa.UUID(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="medium", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="new", nullable=False),
        sa.Column("assignee", sa.String(length=120), nullable=True),
        sa.Column("snoozed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fingerprint", sa.String(length=200), nullable=False),
        sa.Column("event_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entities", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        *_timestamps(),
    )
    op.create_index("ix_alerts_organization_id", "alerts", ["organization_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_sla_due_at", "alerts", ["sla_due_at"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])
    op.create_index("ix_alerts_last_seen_at", "alerts", ["last_seen_at"])

    # --- response_actions ----------------------------------------------------
    op.create_table(
        "response_actions",
        sa.Column(
            "organization_id",
            sa.UUID(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.UUID(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "alert_id",
            sa.UUID(),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("target_type", sa.String(length=24), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
    )
    op.create_index("ix_response_actions_organization_id", "response_actions", ["organization_id"])
    op.create_index("ix_response_actions_incident_id", "response_actions", ["incident_id"])
    op.create_index("ix_response_actions_alert_id", "response_actions", ["alert_id"])
    op.create_index("ix_response_actions_status", "response_actions", ["status"])


def downgrade() -> None:
    op.drop_table("response_actions")
    op.drop_table("alerts")
    op.drop_table("data_sources")
    op.drop_column("incidents", "alert_ids")
    op.drop_column("incidents", "entities")
    op.drop_column("incidents", "timeline")
    op.drop_column("detection_rules", "threshold")
    op.drop_column("detection_rules", "group_by")
    op.drop_column("detection_rules", "window_seconds")
    op.drop_column("detection_rules", "mitre_technique")
    op.drop_column("detection_rules", "mitre_tactic")
    op.drop_column("detection_rules", "description")
    op.drop_index("ix_security_events_source", table_name="security_events")
    op.drop_index("ix_security_events_account", table_name="security_events")
    op.drop_index("ix_security_events_event_type", table_name="security_events")
    op.drop_column("security_events", "raw")
    op.drop_column("security_events", "source")
    op.drop_column("security_events", "parent_process")
    op.drop_column("security_events", "file_path")
    op.drop_column("security_events", "command_line")
    op.drop_column("security_events", "process_name")
    op.drop_column("security_events", "account")
    op.drop_column("security_events", "event_type")
