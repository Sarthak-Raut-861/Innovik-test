"""TRUSTPULSE trust platform schema

Adds the TRUSTPULSE platform entities: users, devices, Trusted Core / Adaptive
Shadow baselines, derived behavioral features, trust-state history, security
events (evidence), action risk profiles, action attempts, Trust Receipts, proof
records and platform incidents. Also extends ``sessions`` with identity, network
context, TCI and containment columns.

Privacy: no passwords (only salted digests), no raw keystrokes, no raw
behavioral recordings, no raw IP addresses (SHA-256 digests only).

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("external_user_id", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("department", sa.String(length=64), nullable=True),
        sa.Column("email_hash", sa.String(length=64), nullable=True),
        sa.Column("credential_hash", sa.String(length=256), nullable=True),
        sa.Column("credential_salt", sa.String(length=64), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("default_auth_method", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_users_active", "users", ['is_active'], unique=False)
    op.create_index("ix_users_tenant_external", "users", ['customer_tenant_id', 'external_user_id'], unique=True)
    op.create_index("ix_users_tenant_username", "users", ['customer_tenant_id', 'username'], unique=True)

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("device_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_sessions_user_ref_id"), nullable=True),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("platform", sa.String(length=64), nullable=True),
        sa.Column("browser", sa.String(length=64), nullable=True),
        sa.Column("os_name", sa.String(length=64), nullable=True),
        sa.Column("screen", sa.String(length=32), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=True),
        sa.Column("trust_level", sa.String(length=16), nullable=False),
        sa.Column("is_registered", sa.Boolean(), nullable=False),
        sa.Column("is_flagged", sa.Boolean(), nullable=False),
        sa.Column("flag_reason", sa.String(length=128), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_devices_tenant_fingerprint", "devices", ['customer_tenant_id', 'device_fingerprint'], unique=True)
    op.create_index("ix_devices_trust_level", "devices", ['trust_level'], unique=False)
    op.create_index("ix_devices_user", "devices", ['user_id'], unique=False)

    op.create_table(
        "trusted_baselines",
        sa.Column("rejected_observations", sa.Integer(), nullable=False),
        sa.Column("promotions_from_shadow", sa.Integer(), nullable=False),
        sa.Column("last_promotion_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_sessions_user_ref_id"), nullable=False),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id", ondelete="CASCADE", name="fk_sessions_device_ref_id"), nullable=True),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("baseline", sa.JSON(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ux_trusted_baselines_tenant_user_device", "trusted_baselines", ['customer_tenant_id', 'user_id', 'device_id'], unique=True)

    op.create_table(
        "shadow_baselines",
        sa.Column("rejected_observations", sa.Integer(), nullable=False),
        sa.Column("quarantine_count", sa.Integer(), nullable=False),
        sa.Column("last_promotion_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_promotion_reasons", sa.JSON(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_sessions_user_ref_id"), nullable=False),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("devices.id", ondelete="CASCADE", name="fk_sessions_device_ref_id"), nullable=True),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("baseline", sa.JSON(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ux_shadow_baselines_tenant_user_device", "shadow_baselines", ['customer_tenant_id', 'user_id', 'device_id'], unique=True)

    op.create_table(
        "behavior_features",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("device_id", sa.String(length=36), nullable=True),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("sample_metadata", sa.JSON(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("anomaly_reasons", sa.JSON(), nullable=True),
        sa.Column("deviations", sa.JSON(), nullable=True),
        sa.Column("features_compared", sa.Integer(), nullable=False),
        sa.Column("detector_method", sa.String(length=48), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_behavior_features_session_time", "behavior_features", ['session_id', 'observed_at'], unique=False)
    op.create_index("ix_behavior_features_user", "behavior_features", ['user_id'], unique=False)

    op.create_table(
        "trust_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("tci", sa.Float(), nullable=False),
        sa.Column("previous_tci", sa.Float(), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("previous_state", sa.String(length=16), nullable=True),
        sa.Column("state_changed", sa.Boolean(), nullable=False),
        sa.Column("raw_band", sa.String(length=16), nullable=True),
        sa.Column("hysteresis_applied", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.String(length=8), nullable=False),
        sa.Column("trend", sa.String(length=20), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=True),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_trust_states_session_time", "trust_states", ['session_id', 'observed_at'], unique=False)
    op.create_index("ix_trust_states_state", "trust_states", ['state'], unique=False)

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("device_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_security_events_session_time", "security_events", ['session_id', 'observed_at'], unique=False)
    op.create_index("ix_security_events_severity", "security_events", ['severity'], unique=False)
    op.create_index("ix_security_events_type", "security_events", ['event_type'], unique=False)

    op.create_table(
        "action_risk_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
        sa.Column("sensitivity", sa.Float(), nullable=False),
        sa.Column("privilege", sa.Float(), nullable=False),
        sa.Column("resource_exposure", sa.Float(), nullable=False),
        sa.Column("impact", sa.Float(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ux_action_risk_profiles_tenant_action", "action_risk_profiles", ['customer_tenant_id', 'action'], unique=True)

    op.create_table(
        "actions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=36), sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=True),
        sa.Column("action_risk", sa.Integer(), nullable=False),
        sa.Column("risk_breakdown", sa.JSON(), nullable=True),
        sa.Column("tci_at_decision", sa.Float(), nullable=True),
        sa.Column("trust_state_at_decision", sa.String(length=16), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("decision_reason", sa.String(length=128), nullable=True),
        sa.Column("policy_version", sa.String(length=16), nullable=True),
        sa.Column("receipt_id", sa.String(length=64), nullable=True),
        sa.Column("step_up_required", sa.Boolean(), nullable=False),
        sa.Column("step_up_result", sa.String(length=16), nullable=True),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_actions_action", "actions", ['action'], unique=False)
    op.create_index("ix_actions_decision", "actions", ['decision'], unique=False)
    op.create_index("ix_actions_session_time", "actions", ['session_id', 'requested_at'], unique=False)

    op.create_table(
        "trust_receipts",
        sa.Column("receipt_id", sa.String(length=64), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=True),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("tci", sa.Float(), nullable=False),
        sa.Column("action_risk", sa.Integer(), nullable=False),
        sa.Column("trust_state", sa.String(length=16), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("policy_version", sa.String(length=16), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=True),
        sa.Column("factors", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=512), nullable=True),
        sa.Column("hash_algorithm", sa.String(length=16), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("proof_record_id", sa.String(length=36), sa.ForeignKey("proof_records.id", ondelete="SET NULL"), nullable=True),
        sa.Column("merkle_leaf", sa.String(length=64), nullable=True),
        sa.Column("action_record_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('receipt_id'),
    )
    op.create_index("ix_trust_receipts_decision", "trust_receipts", ['decision'], unique=False)
    op.create_index("ix_trust_receipts_issued", "trust_receipts", ['issued_at'], unique=False)
    op.create_index("ix_trust_receipts_proof", "trust_receipts", ['proof_record_id'], unique=False)
    op.create_index("ix_trust_receipts_session", "trust_receipts", ['session_id'], unique=False)
    op.create_index("ux_trust_receipts_nonce", "trust_receipts", ['customer_tenant_id', 'nonce'], unique=True)

    op.create_table(
        "proof_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("batch_id", sa.String(length=64), nullable=False),
        sa.Column("merkle_root", sa.String(length=64), nullable=False),
        sa.Column("leaf_count", sa.Integer(), nullable=False),
        sa.Column("leaf_hashes", sa.JSON(), nullable=True),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("proof_version", sa.String(length=16), nullable=False),
        sa.Column("adapter", sa.String(length=32), nullable=False),
        sa.Column("anchored", sa.Boolean(), nullable=False),
        sa.Column("anchor_reference", sa.String(length=128), nullable=True),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_proof_records_anchored", "proof_records", ['anchored'], unique=False)
    op.create_index("ix_proof_records_root", "proof_records", ['merkle_root'], unique=False)
    op.create_index("ux_proof_records_batch", "proof_records", ['customer_tenant_id', 'batch_id'], unique=True)

    op.create_table(
        "platform_incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("customer_tenant_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("device_id", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=190), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("tci_at_detection", sa.Float(), nullable=True),
        sa.Column("trust_state_at_detection", sa.String(length=16), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("containment_actions", sa.JSON(), nullable=True),
        sa.Column("receipt_ids", sa.JSON(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index("ix_platform_incidents_session", "platform_incidents", ['session_id'], unique=False)
    op.create_index("ix_platform_incidents_severity", "platform_incidents", ['severity'], unique=False)
    op.create_index("ix_platform_incidents_status", "platform_incidents", ['status'], unique=False)

    # Batch mode: portable across PostgreSQL (plain ALTER) and SQLite
    # (copy-and-move), which cannot ALTER in a foreign-key constraint.
    with op.batch_alter_table("sessions", recreate="always") as batch_op:
        batch_op.add_column(sa.Column("user_ref_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_sessions_user_ref_id"), nullable=True))
        batch_op.add_column(sa.Column("device_ref_id", sa.String(length=36), sa.ForeignKey("devices.id", ondelete="CASCADE", name="fk_sessions_device_ref_id"), nullable=True))
        batch_op.add_column(sa.Column("application_id", sa.String(length=64), nullable=False, server_default=sa.text('trustdev')))
        batch_op.add_column(sa.Column("auth_method", sa.String(length=32), nullable=False, server_default=sa.text('PASSWORD')))
        batch_op.add_column(sa.Column("mfa_used", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("identity_assurance", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("ip_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("network_country", sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column("network_asn", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("is_vpn", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("is_proxy_or_tor", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("baseline_network_country", sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column("baseline_network_asn", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("tci", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("previous_tci", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("tci_confidence", sa.String(length=8), nullable=False, server_default=sa.text('LOW')))
        batch_op.add_column(sa.Column("tci_trend", sa.String(length=20), nullable=False, server_default=sa.text('INSUFFICIENT_DATA')))
        batch_op.add_column(sa.Column("trust_state", sa.String(length=16), nullable=False, server_default=sa.text('TRUSTED')))
        batch_op.add_column(sa.Column("trust_state_since", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("trust_evaluations", sa.Integer(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column("last_trust_evaluation_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("is_contained", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("containment_reason", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("revocation_reason", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("pending_step_up", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("step_up_failures", sa.Integer(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column("extra", sa.JSON(), nullable=True))
        batch_op.alter_column("application_id", server_default=None)
        batch_op.alter_column("auth_method", server_default=None)
        batch_op.alter_column("mfa_used", server_default=None)
        batch_op.alter_column("is_vpn", server_default=None)
        batch_op.alter_column("is_proxy_or_tor", server_default=None)
        batch_op.alter_column("tci_confidence", server_default=None)
        batch_op.alter_column("tci_trend", server_default=None)
        batch_op.alter_column("trust_state", server_default=None)
        batch_op.alter_column("trust_evaluations", server_default=None)
        batch_op.alter_column("is_contained", server_default=None)
        batch_op.alter_column("step_up_failures", server_default=None)
        batch_op.create_index("ix_sessions_created", ['created_at'], unique=False)
        batch_op.create_index("ix_sessions_tci", ['tci'], unique=False)
        batch_op.create_index("ix_sessions_trust_state", ['trust_state'], unique=False)
        batch_op.create_index("ix_sessions_user_ref", ['user_ref_id'], unique=False)


def downgrade() -> None:
    # Roll the sessions columns back FIRST: batch mode reflects the table, and
    # reflection fails once the referenced users/devices tables are gone.
    with op.batch_alter_table("sessions", recreate="always") as batch_op:
        batch_op.drop_index("ix_sessions_created")
        batch_op.drop_index("ix_sessions_tci")
        batch_op.drop_index("ix_sessions_trust_state")
        batch_op.drop_index("ix_sessions_user_ref")
        batch_op.drop_column("extra")
        batch_op.drop_column("step_up_failures")
        batch_op.drop_column("pending_step_up")
        batch_op.drop_column("revocation_reason")
        batch_op.drop_column("revoked_at")
        batch_op.drop_column("containment_reason")
        batch_op.drop_column("is_contained")
        batch_op.drop_column("last_trust_evaluation_at")
        batch_op.drop_column("trust_evaluations")
        batch_op.drop_column("trust_state_since")
        batch_op.drop_column("trust_state")
        batch_op.drop_column("tci_trend")
        batch_op.drop_column("tci_confidence")
        batch_op.drop_column("previous_tci")
        batch_op.drop_column("tci")
        batch_op.drop_column("baseline_network_asn")
        batch_op.drop_column("baseline_network_country")
        batch_op.drop_column("is_proxy_or_tor")
        batch_op.drop_column("is_vpn")
        batch_op.drop_column("network_asn")
        batch_op.drop_column("network_country")
        batch_op.drop_column("ip_hash")
        batch_op.drop_column("identity_assurance")
        batch_op.drop_column("mfa_used")
        batch_op.drop_column("auth_method")
        batch_op.drop_column("application_id")
        batch_op.drop_column("device_ref_id")
        batch_op.drop_column("user_ref_id")

    op.drop_index("ix_platform_incidents_session", table_name="platform_incidents")
    op.drop_index("ix_platform_incidents_severity", table_name="platform_incidents")
    op.drop_index("ix_platform_incidents_status", table_name="platform_incidents")
    op.drop_table("platform_incidents")
    op.drop_index("ix_proof_records_anchored", table_name="proof_records")
    op.drop_index("ix_proof_records_root", table_name="proof_records")
    op.drop_index("ux_proof_records_batch", table_name="proof_records")
    op.drop_table("proof_records")
    op.drop_index("ix_trust_receipts_decision", table_name="trust_receipts")
    op.drop_index("ix_trust_receipts_issued", table_name="trust_receipts")
    op.drop_index("ix_trust_receipts_proof", table_name="trust_receipts")
    op.drop_index("ix_trust_receipts_session", table_name="trust_receipts")
    op.drop_index("ux_trust_receipts_nonce", table_name="trust_receipts")
    op.drop_table("trust_receipts")
    op.drop_index("ix_actions_action", table_name="actions")
    op.drop_index("ix_actions_decision", table_name="actions")
    op.drop_index("ix_actions_session_time", table_name="actions")
    op.drop_table("actions")
    op.drop_index("ux_action_risk_profiles_tenant_action", table_name="action_risk_profiles")
    op.drop_table("action_risk_profiles")
    op.drop_index("ix_security_events_session_time", table_name="security_events")
    op.drop_index("ix_security_events_severity", table_name="security_events")
    op.drop_index("ix_security_events_type", table_name="security_events")
    op.drop_table("security_events")
    op.drop_index("ix_trust_states_session_time", table_name="trust_states")
    op.drop_index("ix_trust_states_state", table_name="trust_states")
    op.drop_table("trust_states")
    op.drop_index("ix_behavior_features_session_time", table_name="behavior_features")
    op.drop_index("ix_behavior_features_user", table_name="behavior_features")
    op.drop_table("behavior_features")
    op.drop_index("ux_shadow_baselines_tenant_user_device", table_name="shadow_baselines")
    op.drop_table("shadow_baselines")
    op.drop_index("ux_trusted_baselines_tenant_user_device", table_name="trusted_baselines")
    op.drop_table("trusted_baselines")
    op.drop_index("ix_devices_tenant_fingerprint", table_name="devices")
    op.drop_index("ix_devices_trust_level", table_name="devices")
    op.drop_index("ix_devices_user", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_users_active", table_name="users")
    op.drop_index("ix_users_tenant_external", table_name="users")
    op.drop_index("ix_users_tenant_username", table_name="users")
    op.drop_table("users")
