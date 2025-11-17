# app/crypto/aes.py
"""AES-128(ECB)+PKCS#7 helpers."""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Tuple


BLOCK_SIZE = 16  # AES block size in bytes
KEY_SIZE = 16  # AES-128


def random_aes_key() -> bytes:
    """Return a secure random 16-byte AES-128 key."""
    return get_random_bytes(KEY_SIZE)


def aes128_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-128 in ECB mode using PKCS#7 padding.
    - key: must be 16 bytes
    - plaintext: bytes
    Returns ciphertext bytes.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError("key must be 16 bytes (AES-128)")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return ct


def aes128_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext with AES-128 in ECB mode and remove PKCS#7 padding.
    - key: 16 bytes
    - ciphertext: bytes (must be multiple of 16)
    Returns plaintext bytes.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError("key must be 16 bytes (AES-128)")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a multiple of 16 bytes")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    pt = unpad(padded, BLOCK_SIZE)
    return pt
