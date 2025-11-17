#!/usr/bin/env python3
"""
Create Root CA (RSA + self-signed X.509) using cryptography.

Writes two files:
 - <out_key>  (PEM, private key)
 - <out_cert> (PEM, self-signed certificate)
"""

import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption


def create_root_ca(common_name: str, key_path: str, cert_path: str, days: int = 3650, password: str | None = None):
    # generate RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # subject and issuer are same for self-signed CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        # Basic constraints: CA:TRUE
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # Key usage
        .add_extension(
            x509.KeyUsage(digital_signature=True,
                          content_commitment=True,
                          key_encipherment=False,
                          data_encipherment=False,
                          key_agreement=False,
                          key_cert_sign=True,
                          crl_sign=True,
                          encipher_only=False,
                          decipher_only=False),
            critical=True
        )
    )

    cert = cert_builder.sign(private_key=key, algorithm=hashes.SHA256())

    # Write private key
    enc = NoEncryption()
    if password:
        enc = BestAvailableEncryption(password.encode("utf-8"))

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def main():
    p = argparse.ArgumentParser(description="Generate a self-signed Root CA (key + cert).")
    p.add_argument("--cn", default="SecureChat Test CA", help="Common Name for the CA")
    p.add_argument("--out-key", default="certs/ca.key.pem", help="Output private key path (PEM).")
    p.add_argument("--out-cert", default="certs/ca.pem", help="Output certificate path (PEM).")
    p.add_argument("--days", type=int, default=3650, help="Validity in days (default 10 years).")
    p.add_argument("--password", default=None, help="Encrypt private key using this password (optional).")
    args = p.parse_args()

    # ensure output directory exists
    import os
    os.makedirs(os.path.dirname(args.out_key) or ".", exist_ok=True)

    key, cert = create_root_ca(args.cn, args.out_key, args.out_cert, days=args.days, password=args.password)
    print("Wrote CA key ->", args.out_key)
    print("Wrote CA cert ->", args.out_cert)


if __name__ == "__main__":
    main()
