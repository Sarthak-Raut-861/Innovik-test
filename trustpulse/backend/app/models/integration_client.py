"""
TrustPulse AI — Customer Integration Credential Model.

A customer integration maps one tenant to:
  * a non-secret public key used by the browser SDK for identification, and
  * a server-side API key hash used by the customer's application for
    authorized API calls (sessions, risk evaluation, incidents, actions).

The plaintext API key is never stored or logged.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class IntegrationClientModel(Base):
    __tablename__ = "integration_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    api_key_hint: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False
    )  # ACTIVE, DISABLED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index("ix_integration_clients_public_key", "public_key", unique=True),
        Index("ix_integration_clients_api_key_hash", "api_key_hash", unique=True),
        Index("ix_integration_clients_tenant", "customer_tenant_id"),
    )
