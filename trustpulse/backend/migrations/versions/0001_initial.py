"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "integration_clients",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=False),
        sa.Column("api_key_hint", sa.String(length=8), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_integration_clients_api_key_hash", "integration_clients", ["api_key_hash"], unique=True
    )
    op.create_index(
        "ix_integration_clients_public_key", "integration_clients", ["public_key"], unique=True
    )
    op.create_index(
        "ix_integration_clients_tenant", "integration_clients", ["customer_tenant_id"], unique=False
    )

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=True),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("sdk_instance_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("session_version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sessions_tenant_session", "sessions", ["customer_tenant_id", "session_id"], unique=True
    )
    op.create_index("ix_sessions_status", "sessions", ["status"], unique=False)
    op.create_index(
        "ix_sessions_subject", "sessions", ["customer_tenant_id", "subject_id"], unique=False
    )

    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("sdk_instance_id", sa.String(length=64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.BigInteger(), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("feature_payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validation_status", sa.String(length=32), nullable=False),
        sa.Column("rejection_reason", sa.String(length=256), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_telemetry_tenant_event",
        "telemetry_events",
        ["customer_tenant_id", "event_id"],
        unique=True,
    )
    op.create_index(
        "ix_telemetry_tenant_session_seq",
        "telemetry_events",
        ["customer_tenant_id", "session_id", "sequence_number"],
        unique=False,
    )
    op.create_index("ix_telemetry_timestamp", "telemetry_events", ["timestamp"], unique=False)

    op.create_table(
        "behavioral_profiles",
        sa.Column("profile_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("feature_schema_version", sa.String(length=32), nullable=False),
        sa.Column("trusted_baseline", sa.JSON(), nullable=True),
        sa.Column("trusted_baseline_previous", sa.JSON(), nullable=True),
        sa.Column("candidate_baseline", sa.JSON(), nullable=True),
        sa.Column("baseline_version", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("profile_id"),
    )
    op.create_index(
        "ix_profiles_tenant_subject_device",
        "behavioral_profiles",
        ["customer_tenant_id", "subject_id", "device_id"],
        unique=True,
    )

    op.create_table(
        "risk_assessments",
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("behavior_signal", sa.Float(), nullable=False),
        sa.Column("device_signal", sa.Float(), nullable=False),
        sa.Column("network_signal", sa.Float(), nullable=False),
        sa.Column("session_history_signal", sa.Float(), nullable=False),
        sa.Column("session_confidence", sa.Integer(), nullable=False),
        sa.Column("confidence_level", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("assessment_id"),
    )
    op.create_index(
        "ix_risk_assessments_tenant_session",
        "risk_assessments",
        ["customer_tenant_id", "session_id"],
        unique=False,
    )
    op.create_index(
        "ix_risk_assessments_created_at", "risk_assessments", ["created_at"], unique=False
    )

    op.create_table(
        "action_requests",
        sa.Column("action_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("amount", sa.Float(), nullable=True),
        sa.Column("currency", sa.String(length=16), nullable=True),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("action_id"),
    )
    op.create_index(
        "ix_action_requests_tenant_session",
        "action_requests",
        ["customer_tenant_id", "session_id"],
        unique=False,
    )

    op.create_table(
        "security_decisions",
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("action_id", sa.String(length=36), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("policy_rule_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("decision_id"),
    )
    op.create_index(
        "ix_security_decisions_tenant_session",
        "security_decisions",
        ["customer_tenant_id", "session_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_decisions_decision", "security_decisions", ["decision"], unique=False
    )

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trigger_reason", sa.String(length=256), nullable=False),
        sa.Column("decision_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("incident_id"),
    )
    op.create_index(
        "ix_incidents_tenant_status", "incidents", ["customer_tenant_id", "status"], unique=False
    )
    op.create_index(
        "ix_incidents_tenant_session",
        "incidents",
        ["customer_tenant_id", "session_id"],
        unique=False,
    )

    op.create_table(
        "audit_logs",
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("metadata_payload", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("audit_id"),
    )
    op.create_index(
        "ix_audit_logs_tenant_timestamp",
        "audit_logs",
        ["customer_tenant_id", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_audit_logs_tenant_event",
        "audit_logs",
        ["customer_tenant_id", "event_type"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_logs_tenant_event", table_name="audit_logs")
    op.drop_index("ix_audit_logs_tenant_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_incidents_tenant_session", table_name="incidents")
    op.drop_index("ix_incidents_tenant_status", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_security_decisions_decision", table_name="security_decisions")
    op.drop_index("ix_security_decisions_tenant_session", table_name="security_decisions")
    op.drop_table("security_decisions")
    op.drop_index("ix_action_requests_tenant_session", table_name="action_requests")
    op.drop_table("action_requests")
    op.drop_index("ix_risk_assessments_created_at", table_name="risk_assessments")
    op.drop_index("ix_risk_assessments_tenant_session", table_name="risk_assessments")
    op.drop_table("risk_assessments")
    op.drop_index("ix_profiles_tenant_subject_device", table_name="behavioral_profiles")
    op.drop_table("behavioral_profiles")
    op.drop_index("ix_telemetry_timestamp", table_name="telemetry_events")
    op.drop_index("ix_telemetry_tenant_session_seq", table_name="telemetry_events")
    op.drop_index("ix_telemetry_tenant_event", table_name="telemetry_events")
    op.drop_table("telemetry_events")
    op.drop_index("ix_sessions_subject", table_name="sessions")
    op.drop_index("ix_sessions_status", table_name="sessions")
    op.drop_index("ix_sessions_tenant_session", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_integration_clients_tenant", table_name="integration_clients")
    op.drop_index("ix_integration_clients_public_key", table_name="integration_clients")
    op.drop_index("ix_integration_clients_api_key_hash", table_name="integration_clients")
    op.drop_table("integration_clients")
