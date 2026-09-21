"""
SecureMailScope - Cryptographic Security & Authentication Utilities
Implements PBKDF2-HMAC-SHA256 password hashing with 600,000 iterations,
cryptographic salt generation, and HMAC-SHA256 signed session tokens.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional, Dict, Any

from securemailscope.core.config import config

SALT_BYTES = 16
HASH_ITERATIONS = 600_000
HASH_ALGO = "sha256"
TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days
_REVOKED_TOKENS = set()
_EPHEMERAL_SIGNING_SECRET = secrets.token_urlsafe(48)


def revoke_token(token: str) -> None:
    """Revoke a session token so subsequent requests are rejected."""
    if token:
        _REVOKED_TOKENS.add(token.strip())


def is_token_revoked(token: str) -> bool:
    """Check if token was revoked via logout."""
    return token.strip() in _REVOKED_TOKENS if token else False


def hash_password(password: str) -> str:
    """Hash a plaintext password using PBKDF2-HMAC-SHA256 with 600k rounds."""
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        HASH_ALGO,
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    derived_b64 = base64.b64encode(derived).decode("ascii")
    return f"pbkdf2:{HASH_ALGO}:{HASH_ITERATIONS}${salt_b64}${derived_b64}"


def verify_password(plain_password: str, hashed: str) -> bool:
    """Safely verify a password against its stored hash using constant-time comparison."""
    try:
        header, salt_b64, derived_b64 = hashed.split("$")
        algo_info = header.split(":")
        iterations = int(algo_info[2])
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_derived = base64.b64decode(derived_b64.encode("ascii"))

        actual_derived = hashlib.pbkdf2_hmac(
            HASH_ALGO,
            plain_password.encode("utf-8"),
            salt,
            iterations
        )
        return hmac.compare_digest(actual_derived, expected_derived)
    except Exception:
        return False


def _get_signing_secret() -> bytes:
    # Never use a source-controlled/default secret. A development process
    # without SECRET_KEY gets a non-persistent random key; production config
    # rejects this state in core.config.
    key = getattr(config, "secret_key", None) or _EPHEMERAL_SIGNING_SECRET
    return key.encode("utf-8")


def create_access_token(data: Dict[str, Any], expires_in: int = TOKEN_TTL_SECONDS) -> str:
    """Generate an HMAC-SHA256 signed session token."""
    payload = dict(data)
    payload["exp"] = int(time.time()) + expires_in
    payload["iat"] = int(time.time())
    
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    
    signature = hmac.new(_get_signing_secret(), payload_b64.encode("ascii"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    
    return f"{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify an HMAC-SHA256 signed session token and return its payload if valid."""
    try:
        if not token or is_token_revoked(token):
            return None

        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        
        # Pad base64 strings
        rem_p = len(payload_b64) % 4
        if rem_p:
            payload_b64_padded = payload_b64 + "=" * (4 - rem_p)
        else:
            payload_b64_padded = payload_b64

        rem_s = len(sig_b64) % 4
        if rem_s:
            sig_b64_padded = sig_b64 + "=" * (4 - rem_s)
        else:
            sig_b64_padded = sig_b64

        expected_sig = hmac.new(_get_signing_secret(), payload_b64.encode("ascii"), hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64_padded.encode("ascii"))
        
        if not hmac.compare_digest(actual_sig, expected_sig):
            return None
            
        payload_bytes = base64.urlsafe_b64decode(payload_b64_padded.encode("ascii"))
        payload = json.loads(payload_bytes.decode("utf-8"))
        
        if payload.get("exp", 0) < time.time():
            return None
            
        return payload
    except Exception:
        return None
