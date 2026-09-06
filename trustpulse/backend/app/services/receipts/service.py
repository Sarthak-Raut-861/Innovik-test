"""TRUSTPULSE — Trust Receipts.

A receipt is the answer to "why was this action allowed, challenged or blocked?"
It is a signed statement of the decision *and* the evidence behind it, bound to a
specific user + device + session + action + resource + nonce, with a short
expiry.

Binding matters. An unbound receipt is a bearer token: capture one ALLOW for
`VIEW_DASHBOARD` and you have argued for anything. Binding means the receipt is
only true of that exact tuple, and the nonce makes it single-use.

Integrity model:

* `evidence_hash` — SHA-256 over the canonical serialization of the evidence
  list. Changing one word of one evidence record changes this hash.
* `receipt_hash` — SHA-256 over the canonical serialization of every bound field
  plus `evidence_hash`. This is what a verifier recomputes.

Serialization is canonical (sorted keys, no whitespace, explicit float
formatting) so the hash does not depend on dict ordering or JSON library
quirks. Phase 3 adds Merkle batching and anchoring on top of `receipt_hash`;
this module deliberately knows nothing about chains.

The receipt never contains raw behavioral data — only the evidence descriptions
and factor scores the trust engine chose to emit.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.receipts import TrustReceiptModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(payload: Any) -> str:
    """Deterministic JSON serialization.

    Sorted keys and fixed separators, so two equal payloads always produce the
    same bytes and therefore the same hash. Non-ASCII is escaped rather than
    passed through, so the hash cannot depend on the transport encoding.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_timestamp(value: datetime) -> str:
    """Renders a datetime identically whether it is aware, naive, or DB-loaded.

    This is load-bearing for the receipt hash. An in-memory datetime is
    timezone-aware (`...+00:00`); the same instant read back out of SQLite is
    naive (`...` with no offset). Hashing `isoformat()` directly therefore
    produced a different digest for a receipt that had merely been persisted —
    every issued receipt would have failed verification.

    Naive values are interpreted as UTC, which is what the models write.
    Microseconds are truncated so the digest does not depend on the storage
    backend's timestamp precision.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_evidence(evidence: List[Dict[str, Any]], algorithm: str = "sha256") -> str:
    """Hashes the evidence list into a single digest.

    Only the fields that matter for the decision are folded in: an added
    timestamp must not invalidate a receipt, but a changed description or
    severity must.
    """
    normalized = [
        {
            "type": item.get("type"),
            "severity": _round_float(item.get("severity")),
            "description": item.get("description"),
            "source": item.get("source"),
        }
        for item in (evidence or [])
    ]
    normalized.sort(key=lambda item: (str(item["type"]), str(item["description"])))
    if algorithm == "sha256":
        return sha256_hex(canonical_json(normalized))
    raise ValueError(f"unsupported evidence hash algorithm: {algorithm}")


def _round_float(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 4)


def receipt_payload(
    *,
    receipt_id: str,
    user_id: str,
    device_id: str,
    session_id: str,
    action: str,
    resource: Optional[str],
    nonce: str,
    tci: float,
    action_risk: int,
    trust_state: str,
    decision: str,
    policy_version: str,
    rule_id: Optional[str],
    evidence_hash: str,
    issued_at: datetime,
    expires_at: datetime,
) -> Dict[str, Any]:
    """The canonical field set that `receipt_hash` covers.

    Every field the receipt asserts must appear here. Omitting one would let an
    attacker rewrite it without invalidating the hash.
    """
    return {
        "receipt_id": receipt_id,
        "user_id": user_id,
        "device_id": device_id,
        "session_id": session_id,
        "action": action,
        "resource": resource,
        "nonce": nonce,
        "tci": round(float(tci), 2),
        "action_risk": int(action_risk),
        "trust_state": trust_state,
        "decision": decision,
        "policy_version": policy_version,
        "rule_id": rule_id,
        "evidence_hash": evidence_hash,
        # Canonical rendering: identical for aware, naive and DB-loaded values.
        "issued_at": canonical_timestamp(issued_at),
        "expires_at": canonical_timestamp(expires_at),
    }


def compute_receipt_hash(fields: Dict[str, Any], algorithm: str = "sha256") -> str:
    if algorithm != "sha256":
        raise ValueError(f"unsupported receipt hash algorithm: {algorithm}")
    return sha256_hex(canonical_json(fields))


@dataclass
class ReceiptVerification:
    """Result of verifying a presented receipt."""

    valid: bool
    receipt_id: str
    reasons: List[str]
    hash_matches: bool
    expired: bool = False
    revoked: bool = False
    reused: bool = False
    not_found: bool = False
    binding: Dict[str, Any] | None = None
    verified_at: datetime | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "receipt_id": self.receipt_id,
            "reasons": self.reasons,
            "hash_matches": self.hash_matches,
            "expired": self.expired,
            "revoked": self.revoked,
            "reused": self.reused,
            "not_found": self.not_found,
            "binding": self.binding,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


class ReceiptService:
    """Issues and verifies Trust Receipts for one tenant."""

    def __init__(self, db: AsyncSession, tenant_id: str, config: Optional[TrustModelConfig] = None):
        self.db = db
        self.tenant_id = tenant_id
        self.config = config or get_trust_config()
        receipts = self.config.receipts_config()
        self._ttl_seconds = int(receipts.get("ttl_seconds", 90))
        self._max_ttl = int(receipts.get("max_ttl_seconds", 900))
        self._nonce_bytes = int(receipts.get("nonce_bytes", 16))
        self._algorithm = str(receipts.get("hash_algorithm", "sha256"))
        self._single_use = bool(receipts.get("single_use", True))
        self._evidence_algorithm = str(receipts.get("evidence_hash_algorithm", self._algorithm))

    # ------------------------------------------------------------------ issuing
    def generate_nonce(self) -> str:
        """Cryptographically random, never derived from predictable input."""
        return secrets.token_hex(self._nonce_bytes)

    async def issue(
        self,
        *,
        user_id: str,
        device_id: str,
        session_id: str,
        action: str,
        resource: Optional[str],
        tci: float,
        action_risk: int,
        trust_state: str,
        decision: str,
        policy_version: str,
        rule_id: Optional[str] = None,
        factors: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        explanation: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        nonce: Optional[str] = None,
        action_record_id: Optional[str] = None,
    ) -> TrustReceiptModel:
        """Creates and persists a receipt. Raises on a nonce collision.

        The nonce is unique per tenant by database constraint. A collision means
        either the caller supplied a duplicate nonce (a replay attempt) or the
        RNG produced one — both must fail loudly rather than silently overwrite.
        """
        ttl = int(ttl_seconds if ttl_seconds is not None else self._ttl_seconds)
        ttl = max(1, min(ttl, self._max_ttl))
        issued_at = _now()
        expires_at = issued_at + timedelta(seconds=ttl)

        evidence_list = list(evidence or [])
        evidence_hash = hash_evidence(evidence_list, self._evidence_algorithm)

        # Resolve the nonce BEFORE deriving the receipt id. The id is a function
        # of the binding tuple including the nonce, so generating it later would
        # produce an id that no longer matches the tuple it claims to bind.
        resolved_nonce = nonce or self.generate_nonce()

        # receipt_id is deterministic over the binding tuple + nonce, so a retry
        # of the exact same request cannot mint a second distinct receipt.
        receipt_id = self._receipt_id(
            session_id=session_id,
            action=action,
            resource=resource,
            nonce=resolved_nonce,
        )

        fields = receipt_payload(
            receipt_id=receipt_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            action=action,
            resource=resource,
            nonce=resolved_nonce,
            tci=tci,
            action_risk=action_risk,
            trust_state=trust_state,
            decision=decision,
            policy_version=policy_version,
            rule_id=rule_id,
            evidence_hash=evidence_hash,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        receipt_hash = compute_receipt_hash(fields, self._algorithm)

        receipt = TrustReceiptModel(
            receipt_id=fields["receipt_id"],
            customer_tenant_id=self.tenant_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            action=action,
            resource=resource,
            nonce=fields["nonce"],
            tci=float(tci),
            action_risk=int(action_risk),
            trust_state=trust_state,
            decision=decision,
            policy_version=policy_version,
            rule_id=rule_id,
            factors=factors,
            evidence=evidence_list,
            explanation=explanation,
            evidence_hash=evidence_hash,
            receipt_hash=receipt_hash,
            hash_algorithm=self._algorithm,
            issued_at=issued_at,
            expires_at=expires_at,
            revoked=False,
            action_record_id=action_record_id,
        )
        self.db.add(receipt)
        await self.db.flush()
        return receipt

    @staticmethod
    def _receipt_id(*, session_id: str, action: str, resource: Optional[str], nonce: str) -> str:
        binding = canonical_json(
            {"session_id": session_id, "action": action, "resource": resource, "nonce": nonce}
        )
        return f"trc_{sha256_hex(binding)[:32]}"

    # ------------------------------------------------------------------ queries
    async def get(self, receipt_id: str) -> Optional[TrustReceiptModel]:
        result = await self.db.execute(
            select(TrustReceiptModel).where(
                TrustReceiptModel.customer_tenant_id == self.tenant_id,
                TrustReceiptModel.receipt_id == receipt_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_nonce(self, nonce: str) -> Optional[TrustReceiptModel]:
        result = await self.db.execute(
            select(TrustReceiptModel).where(
                TrustReceiptModel.customer_tenant_id == self.tenant_id,
                TrustReceiptModel.nonce == nonce,
            )
        )
        return result.scalar_one_or_none()

    async def for_session(self, session_id: str, limit: int = 100) -> List[TrustReceiptModel]:
        result = await self.db.execute(
            select(TrustReceiptModel)
            .where(
                TrustReceiptModel.customer_tenant_id == self.tenant_id,
                TrustReceiptModel.session_id == session_id,
            )
            .order_by(TrustReceiptModel.issued_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def revoke(self, receipt_id: str, reason: str = "REVOKED") -> Optional[TrustReceiptModel]:
        receipt = await self.get(receipt_id)
        if receipt is None:
            return None
        receipt.revoked = True
        receipt.explanation = f"{receipt.explanation or ''} [{reason}]".strip()
        await self.db.flush()
        logger.info("Revoked trust receipt %s (%s)", receipt_id, reason)
        return receipt

    # ------------------------------------------------------------------ verification
    async def verify(
        self,
        receipt_id: str,
        *,
        presented: Optional[Dict[str, Any]] = None,
        check_binding: bool = True,
        mark_used: bool = True,
    ) -> ReceiptVerification:
        """Verifies a receipt's integrity, binding, expiry and revocation.

        `presented` optionally carries the fields a caller claims the receipt
        had. Any mismatch against the stored record is a failure — this is what
        makes tampering detectable rather than merely unlikely.

        Returns a structured result rather than raising, because "invalid" is a
        normal, expected outcome that the caller must be able to report.
        """
        reasons: List[str] = []
        receipt = await self.get(receipt_id)

        if receipt is None:
            return ReceiptVerification(
                valid=False,
                receipt_id=receipt_id,
                reasons=["RECEIPT_NOT_FOUND"],
                hash_matches=False,
                not_found=True,
                verified_at=_now(),
            )

        # 1) Recompute the hash from the stored fields.
        fields = receipt_payload(
            receipt_id=receipt.receipt_id,
            user_id=receipt.user_id,
            device_id=receipt.device_id,
            session_id=receipt.session_id,
            action=receipt.action,
            resource=receipt.resource,
            nonce=receipt.nonce,
            tci=receipt.tci,
            action_risk=receipt.action_risk,
            trust_state=receipt.trust_state,
            decision=receipt.decision,
            policy_version=receipt.policy_version,
            rule_id=receipt.rule_id,
            evidence_hash=receipt.evidence_hash,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
        )
        recomputed = compute_receipt_hash(fields, receipt.hash_algorithm or self._algorithm)
        hash_matches = secrets.compare_digest(recomputed, receipt.receipt_hash or "")
        if not hash_matches:
            reasons.append("RECEIPT_HASH_MISMATCH")

        # 2) The evidence digest must still match the stored evidence list.
        stored_evidence_hash = hash_evidence(
            list(receipt.evidence or []), receipt.hash_algorithm or self._algorithm
        )
        if not secrets.compare_digest(stored_evidence_hash, receipt.evidence_hash or ""):
            reasons.append("EVIDENCE_HASH_MISMATCH")

        # 3) Expiry. A receipt is short-lived by design.
        now = _now()
        expires_at = receipt.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        expired = now > expires_at
        if expired:
            reasons.append("RECEIPT_EXPIRED")

        # 4) Revocation.
        revoked = bool(receipt.revoked)
        if revoked:
            reasons.append("RECEIPT_REVOKED")

        # 5) Binding — the presented claim must match what was issued.
        binding_ok = True
        if check_binding and presented:
            for field_name in ("user_id", "device_id", "session_id", "action", "resource", "nonce"):
                if field_name not in presented:
                    continue
                expected = getattr(receipt, field_name)
                if presented[field_name] != expected:
                    reasons.append(f"BINDING_MISMATCH:{field_name}")
                    binding_ok = False

        # 6) Single use.
        reused = False
        if self._single_use:
            meta = dict(receipt.factors or {})
            if meta.get("__presented_at__"):
                reused = True
                reasons.append("RECEIPT_ALREADY_USED")
            elif mark_used:
                meta["__presented_at__"] = now.isoformat()
                receipt.factors = meta
                await self.db.flush()

        valid = not reasons and binding_ok
        return ReceiptVerification(
            valid=valid,
            receipt_id=receipt_id,
            reasons=reasons or ["RECEIPT_VALID"],
            hash_matches=hash_matches,
            expired=expired,
            revoked=revoked,
            reused=reused,
            binding=fields,
            verified_at=now,
        )

    @staticmethod
    def to_public_dict(
        receipt: TrustReceiptModel, *, include_evidence: bool = True
    ) -> Dict[str, Any]:
        """Serializes a receipt for API responses.

        `signature` is intentionally omitted until the signing layer lands in
        Phase 3; exposing a null signature field invites clients to trust a
        receipt that was never signed.
        """
        data: Dict[str, Any] = {
            "receipt_id": receipt.receipt_id,
            "session_id": receipt.session_id,
            "user_id": receipt.user_id,
            "device_id": receipt.device_id,
            "action": receipt.action,
            "resource": receipt.resource,
            "nonce": receipt.nonce,
            "decision": receipt.decision,
            "tci": receipt.tci,
            "action_risk": receipt.action_risk,
            "trust_state": receipt.trust_state,
            "policy_version": receipt.policy_version,
            "rule_id": receipt.rule_id,
            "explanation": receipt.explanation,
            "evidence_hash": receipt.evidence_hash,
            "receipt_hash": receipt.receipt_hash,
            "hash_algorithm": receipt.hash_algorithm,
            "issued_at": receipt.issued_at,
            "expires_at": receipt.expires_at,
            "revoked": receipt.revoked,
            "proof_record_id": receipt.proof_record_id,
            "merkle_leaf": receipt.merkle_leaf,
        }
        if include_evidence:
            data["evidence"] = list(receipt.evidence or [])
            data["factors"] = {
                k: v for k, v in (receipt.factors or {}).items() if not k.startswith("__")
            }
        return data


__all__ = [
    "ReceiptService",
    "ReceiptVerification",
    "canonical_json",
    "canonical_timestamp",
    "sha256_hex",
    "hash_evidence",
    "receipt_payload",
    "compute_receipt_hash",
]
