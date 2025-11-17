# app/crypto/dh.py
"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
from hashlib import sha256
from app.common.utils import b64e, b64d

# -------------------------
# DH parameters (classic)
# -------------------------

# A fixed 2048-bit safe prime and generator 2 is standard for assignments
# You may use any RFC prime; here we generate once for simplicity.
# In a real system these would be fixed constants.

# To remain deterministic across client/server, we use a fixed prime.
# (This is safe for coursework.)

DH_P = int(
    """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
    """.replace("\n", "").replace(" ", ""), 16
)
DH_G = 2


# -------------------------
# Keypair generation
# -------------------------

def dh_generate_keypair():
    """
    Returns: (private_int, public_int)
    """
    private = int.from_bytes(os.urandom(32), "big") % DH_P
    public = pow(DH_G, private, DH_P)
    return private, public


# -------------------------
# Shared secret derivation
# -------------------------

def dh_derive_shared_key(private: int, peer_public: int) -> bytes:
    """
    Computes DH shared secret then derives AES-128 key:

        Ks           = (peer_public ^ private) mod p
        SHA256(Ks)   = 32 bytes
        Trunc16(...) = first 16 bytes  →  AES key

    Returns: 16-byte AES key.
    """
    shared_int = pow(peer_public, private, DH_P)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")

    kdf = sha256(shared_bytes).digest()
    return kdf[:16]   # Trunc16


# -------------------------
# Base64 helpers
# -------------------------

def dh_pub_to_b64(pub: int) -> str:
    b = pub.to_bytes((pub.bit_length() + 7) // 8, "big")
    return b64e(b)

def dh_pub_from_b64(s: str) -> int:
    b = b64d(s)
    return int.from_bytes(b, "big")
