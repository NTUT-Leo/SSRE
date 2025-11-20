"""Cryptographic helpers for password hashing and one-time passwords."""

from __future__ import annotations

import base64
import hmac
import os
import struct
import time
from hashlib import pbkdf2_hmac, sha1
from typing import Tuple

# Cryptographic settings
PBKDF2_ITERATIONS = 120_000
SALT_BYTES = 16
TOTP_INTERVAL = 30
TOTP_DIGITS = 6


def generate_salt() -> bytes:
    """Return a securely generated random salt."""
    return os.urandom(SALT_BYTES)


def hash_password(password: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    """Hash a password using PBKDF2-HMAC-SHA256.

    Args:
        password: Plain-text password. Must not be empty.
        salt: Optional salt. If not provided, a random salt is generated.

    Returns:
        A tuple of (salt, derived_key).
    """
    if not password:
        raise ValueError("Password must not be empty")

    if salt is None:
        salt = generate_salt()

    derived_key = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt, derived_key


def encode_credentials(salt: bytes, derived_key: bytes) -> str:
    """Encode salt and derived key into a base64 string for storage."""
    return base64.b64encode(salt + derived_key).decode("ascii")


def decode_credentials(encoded: str) -> Tuple[bytes, bytes]:
    """Decode the stored credential string back into salt and derived key."""
    raw = base64.b64decode(encoded)
    salt, derived_key = raw[:SALT_BYTES], raw[SALT_BYTES:]
    return salt, derived_key


def verify_password(password: str, encoded_credentials: str) -> bool:
    """Verify a password against stored credentials using constant-time comparison."""
    try:
        salt, stored_key = decode_credentials(encoded_credentials)
    except (ValueError, base64.binascii.Error):
        return False

    _, derived_key = hash_password(password, salt)
    return hmac.compare_digest(stored_key, derived_key)


def generate_totp_secret() -> str:
    """Generate a new Base32-encoded secret for TOTP."""
    return base64.b32encode(os.urandom(20)).decode("ascii")


def _totp_counter(timestamp: float | None = None, interval: int = TOTP_INTERVAL) -> int:
    """Return the moving counter for TOTP based on the timestamp."""
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp // interval)


def _dynamic_truncate(hmac_digest: bytes) -> int:
    """Dynamic truncation step from RFC 4226."""
    offset = hmac_digest[-1] & 0x0F
    code = struct.unpack(">I", hmac_digest[offset : offset + 4])[0]
    return code & 0x7FFFFFFF


def generate_totp(secret: str, timestamp: float | None = None, interval: int = TOTP_INTERVAL) -> str:
    """Generate a TOTP code for the given secret."""
    counter = _totp_counter(timestamp, interval)
    key = base64.b32decode(secret, casefold=True)
    hmac_digest = hmac.new(key, counter.to_bytes(8, "big"), sha1).digest()
    code = _dynamic_truncate(hmac_digest)
    return str(code % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, token: str, window: int = 1, interval: int = TOTP_INTERVAL) -> bool:
    """Verify a user-provided TOTP token within the allowed window."""
    if not token.isdigit() or len(token) != TOTP_DIGITS:
        return False

    current_counter = _totp_counter(interval=interval)
    key = base64.b32decode(secret, casefold=True)
    for delta in range(-window, window + 1):
        counter = current_counter + delta
        hmac_digest = hmac.new(key, counter.to_bytes(8, "big"), sha1).digest()
        code = _dynamic_truncate(hmac_digest) % (10**TOTP_DIGITS)
        if hmac.compare_digest(str(code).zfill(TOTP_DIGITS), token):
            return True
    return False
