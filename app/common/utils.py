"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import time
import base64
import hashlib


def now_ms() -> int:
    """Return current time in milliseconds since Unix epoch."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Base64-encode bytes and return a UTF-8 string."""
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    """Decode a base64-encoded string back to bytes."""
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest of input bytes as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest()
