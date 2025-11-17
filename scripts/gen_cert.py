#!/usr/bin/env python3
"""
Issue server/client cert signed by Root CA (SAN=DNSName(CN)).

Usage:
  python3 scripts/gen_cert.py --ca certs/ca.pem --ca-key certs/ca.key.pem --cn server1 --out certs/server1.pem --key certs/server1.key.pem
"""

import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.backends import default_backend


def load_pem_key(path: str, password: str | None = None):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password.encode() if password else None, backend=default_backend())


def load_pem_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), backend=default_backend())


def issue_cert(ca_cert, ca_key, cn: str, out_cert_path: str, out_key_path: str, days: int = 365, password: str | None = None):
    # generate leaf key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = ca_cert.subject

    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        # SAN: DNSName(CN)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        # Basic constraints: CA:False
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Key usage: digital signature & key encipherment
        .add_extension(
            x509.KeyUsage(digital_signature=True,
                          content_commitment=False,
                          key_encipherment=True,
                          data_encipherment=False,
                          key_agreement=True,
                          key_cert_sign=False,
                          crl_sign=False,
                          encipher_only=False,
                          decipher_only=False),
            critical=True
        )
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # write private key
    enc = NoEncryption()
    if password:
        enc = BestAvailableEncryption(password.encode("utf-8"))

    with open(out_key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )

    with open(out_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def main():
    p = argparse.ArgumentParser(description="Issue a certificate signed by a CA.")
    p.add_argument("--ca", required=True, help="Path to CA cert (PEM)")
    p.add_argument("--ca-key", required=True, help="Path to CA private key (PEM)")
    p.add_argument("--cn", required=True, help="Common Name for the new certificate (also SAN)")
    p.add_argument("--out", dest="out_cert", default=None, help="Output cert path (PEM)")
    p.add_argument("--key", dest="out_key", default=None, help="Output key path (PEM)")
    p.add_argument("--days", type=int, default=365, help="Validity in days")
    p.add_argument("--ca-key-password", default=None, help="Password to decrypt CA private key (if encrypted)")
    p.add_argument("--password", default=None, help="Encrypt generated private key with this password")
    args = p.parse_args()

    out_cert = args.out_cert or f"certs/{args.cn}.pem"
    out_key = args.out_key or f"certs/{args.cn}.key.pem"

    import os
    os.makedirs(os.path.dirname(out_cert) or ".", exist_ok=True)

    ca_cert = load_pem_cert(args.ca)
    ca_key = load_pem_key(args.ca_key, password=args.ca_key_password)

    key, cert = issue_cert(ca_cert, ca_key, args.cn, out_cert, out_key, days=args.days, password=args.password)
    print("Wrote key ->", out_key)
    print("Wrote cert ->", out_cert)


if __name__ == "__main__":
    main()
