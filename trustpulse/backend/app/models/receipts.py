"""TRUSTPULSE — Trust Receipts and Proof Records.

The receipt answers "why was this action allowed, challenged or blocked?". It is
bound to user + device + session + action + resource + nonce and carries a short
expiry, so it cannot be replayed as a general-purpose authorization.

The proof record is the blockchain-facing layer. It stores ONLY a Merkle root,
batch metadata and anchor references — never behavioral data, never user data,
never raw evidence.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class TrustReceiptModel(Base):
    __tablename__ = "trust_receipts"

    receipt_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Binding tuple
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)

    # Decision content
    tci: Mapped[float] = mapped_column(Float, nullable=False)
    action_risk: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_state: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    factors: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Integrity
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    hash_algorithm: Mapped[str] = mapped_column(String(16), default="sha256", nullable=False)

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    proof_record_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("proof_records.id", ondelete="SET NULL"), nullable=True
    )
    merkle_leaf: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    action_record_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("ux_trust_receipts_nonce", "customer_tenant_id", "nonce", unique=True),
        Index("ix_trust_receipts_session", "session_id"),
        Index("ix_trust_receipts_decision", "decision"),
        Index("ix_trust_receipts_issued", "issued_at"),
        Index("ix_trust_receipts_proof", "proof_record_id"),
    )


class ProofRecordModel(Base):
    """Merkle batch anchored to the proof layer. Hashes and metadata only."""

    __tablename__ = "proof_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)

    batch_id: Mapped[str] = mapped_column(String(64), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    leaf_count: Mapped[int] = mapped_column(Integer, nullable=False)
    leaf_hashes: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    algorithm: Mapped[str] = mapped_column(String(32), default="sha256", nullable=False)
    proof_version: Mapped[str] = mapped_column(String(16), default="1.0.0", nullable=False)

    # Adapter: LOCAL_LEDGER | MOCK_CHAIN | <real chain adapter>
    adapter: Mapped[str] = mapped_column(String(32), default="LOCAL_LEDGER", nullable=False)
    anchored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    anchor_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    anchored_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # `metadata` is reserved on DeclarativeBase, so the attribute is `meta`
    # while the column keeps its documented name.
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSON, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("ux_proof_records_batch", "customer_tenant_id", "batch_id", unique=True),
        Index("ix_proof_records_root", "merkle_root"),
        Index("ix_proof_records_anchored", "anchored"),
    )
