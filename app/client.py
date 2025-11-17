#!/usr/bin/env python3
"""
Client for SecureChat assignment (plain TCP).
Performs:
- mutual cert exchange + validation,
- ephemeral DH for control-plane (credentials),
- registration/login,
- session DH for data-plane,
- interactive chat with per-message AES encryption + RSA signatures,
- transcript and final receipt exchange.
"""

import argparse
import base64
import json
import socket
import threading
import time
from hashlib import sha256

from app.common.utils import now_ms, b64e, b64d
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
from app.storage.transcript import Transcript

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA as CryptoRSA


def recv_json_line(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            return line.decode("utf-8")


def send_json_line(conn, obj):
    s = json.dumps(obj)
    conn.sendall(s.encode("utf-8") + b"\n")


def pem_to_crypto_rsa_private(pem_bytes):
    return CryptoRSA.import_key(pem_bytes)


def cert_pem_to_crypto_pubkey(cert_pem: str):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pub = cert.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return CryptoRSA.import_key(pem)


def cert_fingerprint_hex(cert_pem: str) -> str:
    return sha256(cert_pem.encode()).hexdigest()


class SecureChatClient:
    def __init__(self, host, port, cert_path, key_path, ca_path):
        self.host = host
        self.port = port
        self.cert_pem = open(cert_path).read()
        self.key_pem = open(key_path).read()
        self.ca_pem = open(ca_path).read()
        self.priv_rsa = pem_to_crypto_rsa_private(self.key_pem.encode())
        self.transcript = Transcript(path="transcript_client.log")

        # runtime
        self.server_cert_pem = None
        self.server_rsa_pub = None
        self.ephemeral_aes = None
        self.session_aes = None
        self.seqno = 1

    def run(self, do_register=False, username=None, password=None, email="a@b.com"):
        with socket.create_connection((self.host, self.port)) as conn:
            # 1) send hello (cert + nonce)
            nonce = base64.b64encode(sha256(str(time.time()).encode()).digest()).decode()
            send_json_line(conn, {"type": "hello", "client cert": self.cert_pem, "nonce": nonce})

            # 2) receive server hello
            line = recv_json_line(conn)
            if not line:
                print("[client] no server hello")
                return
            obj = json.loads(line)
            if obj.get("type") == "bad_cert":
                print("[client] server reported bad cert")
                return
            self.server_cert_pem = obj.get("server cert")
            # validate server cert
            ok = validate_cert(self.server_cert_pem, self.ca_pem, expected_cn=None if True else "server1")
            if not ok:
                print("[client] SERVER BAD CERT")
                return
            self.server_rsa_pub = cert_pem_to_crypto_pubkey(self.server_cert_pem)
            print("[client] server cert validated")

            # 3) ephemeral DH (control plane)
            a_priv, a_pub = dh_generate_keypair()
            send_json_line(conn, {"type": "dh client", "g": str(DH_G), "p": str(DH_P), "A": str(a_pub)})
            # receive DH server
            line = recv_json_line(conn)
            obj = json.loads(line)
            if obj.get("type") != "dh server":
                print("[client] expected dh server")
                return
            B = int(obj.get("B"))
            ephemeral_key = dh_derive_shared_key(a_priv, B)
            self.ephemeral_aes = ephemeral_key
            print("[client] ephemeral AES derived (control plane)")

            # 4) perform register/login encrypted under ephemeral AES
            creds = {"email": email, "username": username, "password": password}
            payload = json.dumps(creds).encode()
            ct = aes128_ecb_encrypt(self.ephemeral_aes, payload)
            send_json_line(conn, {"type": "register" if do_register else "login", "payload": b64e(ct)})

            # 5) wait for server response
            line = recv_json_line(conn)
            if not line:
                print("[client] no register/login response")
                return
            obj = json.loads(line)
            if obj.get("type") in ("register ok", "login ok"):
                print("[client] auth OK:", obj.get("type"))
            else:
                print("[client] auth failed:", obj)
                return

            # 6) session DH for data plane
            a2_priv, a2_pub = dh_generate_keypair()
            send_json_line(conn, {"type": "dh client", "g": str(DH_G), "p": str(DH_P), "A": str(a2_pub)})
            line = recv_json_line(conn)
            obj = json.loads(line)
            if obj.get("type") != "dh server":
                print("[client] expected dh server (session)")
                return
            B2 = int(obj.get("B"))
            session_key = dh_derive_shared_key(a2_priv, B2)
            self.session_aes = session_key
            print("[client] session AES derived")

            # 7) Start a receiver thread to handle server messages asynchronously
            stop_flag = threading.Event()

            def receiver():
                nonlocal conn
                while not stop_flag.is_set():
                    line = recv_json_line(conn)
                    if not line:
                        break
                    obj = json.loads(line)
                    t = obj.get("type")
                    if t == "msg ok":
                        print(f"[server] msg ok seq={obj.get('seq')}")
                    elif t == "replay":
                        print("[server] reported replay", obj.get("seq"))
                    elif t == "sig fail":
                        print("[server] signature failure reported by server")
                    elif t == "receipt":
                        print("[server] server receipt received:", obj)
                    else:
                        print("[server] got:", obj)

            thr = threading.Thread(target=receiver, daemon=True)
            thr.start()

            # 8) interactive message loop: read from console, encrypt, sign, send
            try:
                while True:
                    text = input("You: ")
                    if text.strip().lower() in ("/quit", "exit"):
                        # send close + request receipt exchange
                        send_json_line(conn, {"type": "close"})
                        break

                    # encrypt plaintext with session AES
                    plaintext = text.encode()
                    ct = aes128_ecb_encrypt(self.session_aes, plaintext)
                    # compute h = SHA256(seqno || ts || ct)
                    ts = now_ms()
                    digest = sha256()
                    digest.update(str(self.seqno).encode())
                    digest.update(str(ts).encode())
                    digest.update(ct)
                    hbytes = digest.digest()
                    sig = rsa_sign(hbytes, self.priv_rsa)
                    msg = {
                        "type": "msg",
                        "seqno": self.seqno,
                        "ts": ts,
                        "ct": b64e(ct),
                        "sig": b64e(sig),
                    }
                    send_json_line(conn, msg)
                    # append to transcript log
                    entry = {
                        "seqno": self.seqno,
                        "ts": ts,
                        "ct": b64e(ct),
                        "sig": b64e(sig),
                        "peer_fp": cert_fingerprint_hex(self.server_cert_pem),
                    }
                    self.transcript.append("msg", entry)
                    self.seqno += 1
                    time.sleep(0.01)
            except KeyboardInterrupt:
                print("Keyboard interrupt, closing")
                send_json_line(conn, {"type": "close"})

            # wait a moment to receive server receipt then produce own receipt and send
            time.sleep(0.5)
            stop_flag.set()
            thr.join(timeout=1)

            # compute transcript hash and sign
            with open(self.transcript.path, "rb") as f:
                content = f.read()
            transcript_hash = sha256(content).digest()
            sig = rsa_sign(transcript_hash, self.priv_rsa)
            receipt = {
                "type": "receipt",
                "peer": "client",
                "first seq": 1,
                "last seq": self.seqno - 1,
                "transcript sha256": transcript_hash.hex(),
                "sig": b64e(sig),
            }
            self.transcript.append("session_receipt", receipt)
            send_json_line(conn, receipt)
            print("[client] sent receipt and exiting")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=5000, type=int)
    p.add_argument("--cert", default="certs/client1.pem")
    p.add_argument("--key", default="certs/client1.key.pem")
    p.add_argument("--ca", default="certs/ca.pem")
    p.add_argument("--register", action="store_true", help="run registration instead of login")
    p.add_argument("--username", default="alice")
    p.add_argument("--password", default="secret123")
    p.add_argument("--email", default="a@b.com")
    args = p.parse_args()

    c = SecureChatClient(args.host, args.port, args.cert, args.key, args.ca)
    c.run(do_register=args.register, username=args.username, password=args.password, email=args.email)


if __name__ == "__main__":
    main()
