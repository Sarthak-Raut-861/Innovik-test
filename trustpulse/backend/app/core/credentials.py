"""Credential handling for the simulated TrustDev login.

**Passwords are never stored.** Only a salted PBKDF2-HMAC-SHA256 digest is kept,
and it exists solely so the demo application can authenticate a user. The trust
engine never reads it — TRUSTPULSE is not an authentication provider and does not
replace MFA or an IAM system.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 210_000
SALT_BYTES = 16
KEY_BYTES = 32
ALGORITHM = "sha256"


def hash_credential(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Returns ``(digest_hex, salt_hex)``. Constant-work, salted."""
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        ALGORITHM, password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_BYTES
    )
    return digest.hex(), salt.hex()


def verify_credential(password: str, digest_hex: str | None, salt_hex: str | None) -> bool:
    """Timing-safe verification. Always performs work to avoid user enumeration."""
    if not digest_hex or not salt_hex:
        # Burn comparable time even when the account has no credential.
        hash_credential(password or "invalid", secrets.token_bytes(SALT_BYTES).hex())
        return False
    candidate, _ = hash_credential(password, salt_hex)
    return hmac.compare_digest(candidate, digest_hex)


def generate_token() -> str:
    """Opaque application session token (the caller stores only its hash)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_identifier(value: str, pepper: str = "") -> str:
    """One-way digest for network identifiers so raw IPs are never persisted."""
    return hashlib.sha256(f"{pepper}:{value}".encode("utf-8")).hexdigest()
