"""
TrustPulse AI — Security Helpers.

Contains timing-safe comparison, FNV-1a checksum (matching Phase 1 SDK),
API-key hashing, and header/session-binding helpers.
"""

import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Optional


class SecurityUtils:
    @staticmethod
    def verify_constant_time(val1: str, val2: str) -> bool:
        """Timing-attack safe string comparison."""
        return secrets.compare_digest(val1, val2)

    @staticmethod
    def compute_fnv1a_checksum(data: str) -> str:
        """
        Computes the 32-bit FNV-1a checksum matching Phase 1
        IntegrityManager.computeChecksum().
        """
        fnv_prime = 0x01000193
        hash_val = 0x811C9DC5
        for char in data:
            hash_val ^= ord(char)
            hash_val = (hash_val * fnv_prime) & 0xFFFFFFFF
        return f"{hash_val:08x}"

    @staticmethod
    def verify_integrity(payload_str: str, expected_checksum: Optional[str]) -> bool:
        """
        Verifies a packet integrity tag against the computed FNV-1a checksum.

        The checksum detects truncation / transport corruption. It is advisory
        because a compromised browser can forge it, and the backend never relies
        on it as authoritative authentication.
        """
        if not expected_checksum:
            return False
        computed = SecurityUtils.compute_fnv1a_checksum(payload_str)
        return hmac.compare_digest(computed.lower(), expected_checksum.lower())

    @staticmethod
    def canonical_json(value: Dict[str, Any]) -> str:
        """Deterministic, compact JSON form used for integrity verification."""
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hashes a customer API key for storage and lookup.

        Only the SHA-256 hash is persisted. The plaintext key is never stored.
        """
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    @staticmethod
    def redact_secrets(value: Any) -> Any:
        """Recursively redacts keys likely to contain secrets (for audit/log payloads)."""
        forbidden = {
            "password",
            "secret",
            "token",
            "authorization",
            "api_key",
            "api-key",
            "otp",
            "code",
            "private_key",
        }
        if isinstance(value, dict):
            return {
                k: "[REDACTED]"
                if any(f in str(k).lower() for f in forbidden)
                else SecurityUtils.redact_secrets(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [SecurityUtils.redact_secrets(item) for item in value]
        return value

    @staticmethod
    def looks_like_secret(value: str) -> bool:
        """Heuristic used to avoid logging obvious credential material."""
        if not value:
            return False
        lowered = value.lower()
        return any(
            marker in lowered
            for marker in (
                "-----begin",
                "private key",
                "bearer ",
                "api-key",
                "x-api-key",
                "authorization:",
            )
        )
