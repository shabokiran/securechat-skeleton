#!/usr/bin/env python3
"""
Server for the SecureChat assignment (single-client, plain TCP).
Follows the PDF protocol: mutual cert exchange, ephemeral DH for control plane,
register/login (encrypted under ephemeral AES), then session DH for messaging.
Messages are JSON per-line.
"""

import argparse
import base64
import json
import socket
import threading
import time
from hashlib import sha256

from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.dh import (
    dh_generate_keypair,
    dh_pub_to_b64,
    dh_pub_from_b64,
    dh_derive_shared_key,
    DH_P,
    DH_G,
)
from app.crypto.aes import aes128_ecb_encrypt, aes128_ecb_decrypt
from app.crypto.sign import sign as rsa_sign, verify as rsa_verify
from app.crypto.pki import validate_cert
from app.storage.db import init_db, create_user, verify_user
from app.storage.transcript import Transcript

# for certificate / key parsing
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA as CryptoRSA


def recv_json_line(conn):
    """Receive a newline-terminated JSON object (bytes->str->json)."""
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            # push rest back by using a small buffer on socket (not easily done),
            # so we return line and leave rest in memory for caller — simpler to assume one message at a time.
            return line.decode("utf-8")


def send_json_line(conn, obj):
    s = json.dumps(obj)
    conn.sendall(s.encode("utf-8") + b"\n")


def pem_to_crypto_rsa_private(pem_bytes):
    """Load private key PEM string into PyCryptodome RSA key for signing."""
    return CryptoRSA.import_key(pem_bytes)


def cert_pem_to_crypto_pubkey(cert_pem: str):
    """Extract public key from cert PEM and return a PyCryptodome RSA public key."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pub = cert.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return CryptoRSA.import_key(pem)


def cert_fingerprint_hex(cert_pem: str) -> str:
    return sha256(cert_pem.encode()).hexdigest()


class SecureChatServer:
    def __init__(self, host, port, cert_path, key_path, ca_path):
        self.host = host
        self.port = port
        self.cert_pem = open(cert_path).read()
        self.key_pem = open(key_path).read()
        self.ca_pem = open(ca_path).read()
        self.priv_rsa = pem_to_crypto_rsa_private(self.key_pem.encode())
        self.transcript = Transcript(path="transcript_server.log")
        init_db()  # initialize users DB (sqlite in your repo)

        # session state (per connection)
        self.client_cert_pem = None
        self.client_rsa_pub = None
        self.ephemeral_aes = None  # control plane key (bytes, 16)
        self.session_aes = None  # data plane key
        self.expected_seq = 1

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(1)
            print(f"[server] listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                print(f"[server] connection from {addr}")
                try:
                    self.handle_conn(conn)
                except Exception as e:
                    print("[server] error handling connection:", e)
                finally:
                    conn.close()
                    print("[server] connection closed, ready for next client")
                    # reset state
                    self.client_cert_pem = None
                    self.client_rsa_pub = None
                    self.ephemeral_aes = None
                    self.session_aes = None
                    self.expected_seq = 1

    def handle_conn(self, conn):
        # 1) Receive client hello (cert + nonce)
        line = recv_json_line(conn)
        if not line:
            print("[server] no hello received")
            return
        obj = json.loads(line)
        if obj.get("type") != "hello":
            print("[server] expected hello, got:", obj.get("type"))
            return
        self.client_cert_pem = obj.get("client cert")
        client_nonce_b64 = obj.get("nonce")
        print("[server] received client hello, validating cert...")

        # 1a) validate client cert against CA
        ok = validate_cert(self.client_cert_pem, self.ca_pem, expected_cn=None if True else "client1")
        # Note: we accept any CN (expected_cn=None) — but you may enforce specific CN matching if needed.
        if not ok:
            print("[server] BAD CERT from client")
            send_json_line(conn, {"type": "bad_cert"})
            return
        print("[server] client cert validated")

        # load client's RSA public key
        self.client_rsa_pub = cert_pem_to_crypto_pubkey(self.client_cert_pem)

        # 2) send server hello (cert + nonce)
        server_nonce = base64.b64encode(sha256(str(time.time()).encode()).digest()).decode()
        send_json_line(conn, {"type": "server hello", "server cert": self.cert_pem, "nonce": server_nonce})
        print("[server] sent server hello")

        # 3) ephemeral DH for control plane (client will start)
        # Receive DH client
        line = recv_json_line(conn)
        if not line:
            print("[server] no dh client received")
            return
        obj = json.loads(line)
        if obj.get("type") != "dh client":
            print("[server] expected dh client, got", obj.get("type"))
            return
        # read p,g,A
        p = int(obj.get("p"))
        g = int(obj.get("g"))
        A = int(obj.get("A"))

        # generate B and derive ephemeral AES
        b_priv, b_pub = dh_generate_keypair()
        B = b_pub
        send_json_line(conn, {"type": "dh server", "B": str(B)})
        ephemeral_key = dh_derive_shared_key(b_priv, A)  # returns 16 bytes
        self.ephemeral_aes = ephemeral_key
        print("[server] ephemeral AES derived (control plane)")

        # 4) expect encrypted register/login message under ephemeral AES
        line = recv_json_line(conn)
        if not line:
            print("[server] no control-plane payload")
            return
        obj = json.loads(line)
        mtype = obj.get("type")
        if mtype not in ("register", "login"):
            print("[server] expected register/login, got", mtype)
            return
        payload_b64 = obj.get("payload")
        payload_bytes = b64d(payload_b64)
        try:
            decrypted = aes128_ecb_decrypt(self.ephemeral_aes, payload_bytes)
        except Exception as e:
            print("[server] failed to decrypt control payload", e)
            send_json_line(conn, {"type": "error", "reason": "decrypt failed"})
            return
        creds = json.loads(decrypted.decode())
        # creds includes email, username, password (plaintext) for simplicity
        if mtype == "register":
            email = creds.get("email")
            username = creds.get("username")
            password = creds.get("password")
            ok = create_user(username, password)
            if ok:
                send_json_line(conn, {"type": "register ok"})
                print("[server] registered user", username)
            else:
                send_json_line(conn, {"type": "register fail", "reason": "duplicate"})
                print("[server] register failed (duplicate)")
                return
        else:  # login
            username = creds.get("username")
            password = creds.get("password")
            ok = verify_user(username, password)
            if ok:
                send_json_line(conn, {"type": "login ok"})
                print("[server] login ok for", username)
            else:
                send_json_line(conn, {"type": "login fail"})
                print("[server] login failed for", username)
                return

        # 5) Now session DH for data plane
        # Receive DH client (session)
        line = recv_json_line(conn)
        if not line:
            print("[server] no dh client (session) received")
            return
        obj = json.loads(line)
        if obj.get("type") != "dh client":
            print("[server] expected dh client (session), got", obj.get("type"))
            return
        A2 = int(obj.get("A"))
        # server computes B2 and derives session key
        b2_priv, b2_pub = dh_generate_keypair()
        B2 = b2_pub
        send_json_line(conn, {"type": "dh server", "B": str(B2)})
        session_key = dh_derive_shared_key(b2_priv, A2)
        self.session_aes = session_key
        print("[server] session AES derived")

        # 6) Enter data plane message loop
        print("[server] entering data plane; expecting messages")
        while True:
            line = recv_json_line(conn)
            if not line:
                print("[server] client disconnected")
                return
            obj = json.loads(line)
            t = obj.get("type")
            if t == "msg":
                seqno = int(obj.get("seqno"))
                ts = int(obj.get("ts"))
                ct_b64 = obj.get("ct")
                sig_b64 = obj.get("sig")
                ct = b64d(ct_b64)
                sig = b64d(sig_b64)

                # 6a) replay check: seqno must be >= expected
                if seqno < self.expected_seq:
                    print("[server] REPLAY detected seqno", seqno, "expected", self.expected_seq)
                    send_json_line(conn, {"type": "replay", "seq": seqno})
                    continue

                # 6b) verify signature
                # reconstruct hash = SHA256(seqno || ts || ct)
                digest = sha256()
                digest.update(str(seqno).encode())
                digest.update(str(ts).encode())
                digest.update(ct)
                hbytes = digest.digest()
                sig_ok = rsa_verify(hbytes, sig, self.client_rsa_pub)
                if not sig_ok:
                    print("[server] SIG FAIL for seq", seqno)
                    send_json_line(conn, {"type": "sig fail", "seq": seqno})
                    continue

                # 6c) decrypt
                try:
                    pt = aes128_ecb_decrypt(self.session_aes, ct)
                except Exception as e:
                    print("[server] decrypt failed:", e)
                    send_json_line(conn, {"type": "decrypt fail", "seq": seqno})
                    continue

                # 6d) accept: print message, append transcript, advance seq
                text = pt.decode()
                print(f"[client msg] seq={seqno} ts={ts} text={text}")
                # append to transcript: store seqno, ts, ct_b64, sig_b64, peer-cert-fingerprint
                entry = {
                    "seqno": seqno,
                    "ts": ts,
                    "ct": ct_b64,
                    "sig": sig_b64,
                    "peer_fp": cert_fingerprint_hex(self.client_cert_pem)
                }
                self.transcript.append("msg", entry)
                self.expected_seq = seqno + 1
                send_json_line(conn, {"type": "msg ok", "seq": seqno})

            elif t == "receipt":
                # client sending final receipt — verify signature matches transcript hash
                print("[server] received client receipt (storing)")
                self.transcript.append("receipt", obj)
            elif t == "close":
                print("[server] client requested close")
                break
            else:
                print("[server] unknown message type:", t)
                send_json_line(conn, {"type": "error", "reason": "unknown type"})

        # 7) On close, server computes transcript hash and signs it, then send receipt
        # compute transcript hash as SHA256 concatenation of lines
        with open(self.transcript.path, "rb") as f:
            content = f.read()
        transcript_hash = sha256(content).digest()
        sig = rsa_sign(transcript_hash, self.priv_rsa)
        receipt = {
            "type": "receipt",
            "peer": "server",
            "first seq": 1,
            "last seq": self.expected_seq - 1,
            "transcript sha256": transcript_hash.hex(),
            "sig": b64e(sig),
        }
        self.transcript.append("session_receipt", receipt)
        send_json_line(conn, receipt)
        print("[server] sent receipt and closed session")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", default=5000, type=int)
    p.add_argument("--cert", default="certs/server1.pem")
    p.add_argument("--key", default="certs/server1.key.pem")
    p.add_argument("--ca", default="certs/ca.pem")
    args = p.parse_args()

    s = SecureChatServer(args.host, args.port, args.cert, args.key, args.ca)
    s.run()


if __name__ == "__main__":
    main()
