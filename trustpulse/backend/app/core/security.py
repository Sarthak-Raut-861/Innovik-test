"""
TrustPulse AI - Security Helpers & Tenant Validation
"""

import hmac
import hashlib
import secrets
from typing import Optional


class SecurityUtils:
    @staticmethod
    def verify_constant_time(val1: str, val2: str) -> bool:
        """Timing-attack safe string comparison."""
        return secrets.compare_digest(val1, val2)

    @staticmethod
    def compute_fnv1a_checksum(data: str) -> str:
        """
        Computes 32-bit FNV-1a checksum matching Phase 1 IntegrityManager.computeChecksum.
        """
        fnv_prime = 0x01000193
        hash_val = 0x811C9DC5
        for char in data:
            hash_val ^= ord(char)
            hash_val = (hash_val * fnv_prime) & 0xFFFFFFFF
        return f"{hash_val:08x}"

    @staticmethod
    def verify_integrity(payload_str: str, expected_checksum: Optional[str]) -> bool:
        """Verifies packet integrity tag against computed FNV-1a checksum."""
        if not expected_checksum:
            return True  # If client did not provide checksum, fallback
        computed = SecurityUtils.compute_fnv1a_checksum(payload_str)
        return secrets.compare_digest(computed.lower(), expected_checksum.lower())
