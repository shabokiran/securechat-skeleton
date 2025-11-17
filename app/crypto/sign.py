# app/crypto/sign.py
"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generate_rsa_keypair(bits: int = 2048):
    """
    Generate RSA keypair.
    Returns: (private_key, public_key) as Crypto.PublicKey.RSA.RsaKey objects
    """
    key = RSA.generate(bits)
    return key, key.publickey()


def sign(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 + SHA-256.
    Returns signature bytes.
    """
    h = SHA256.new(data)
    sig = pkcs1_15.new(private_key).sign(h)
    return sig


def verify(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify signature using RSA PKCS#1 v1.5 + SHA-256.
    Returns True if valid, False otherwise.
    """
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
