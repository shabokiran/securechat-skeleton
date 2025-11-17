# app/crypto/pki.py
"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from datetime import datetime


def validate_cert(cert_pem: str, ca_pem: str, expected_cn: str) -> bool:
    """
    Validate a certificate.
    Returns True if:
        1. signed by CA
        2. currently valid
        3. CN matches expected
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        ca_cert = x509.load_pem_x509_certificate(ca_pem.encode(), default_backend())

        # 1. verify signed by CA using PKCS#1 v1.5
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

        # 2. check validity window
        now = datetime.utcnow()
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            return False

        # 3. check CN
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            return False

        return True
    except Exception:
        return False
