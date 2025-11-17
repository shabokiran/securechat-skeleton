from pydantic import BaseModel


# ---------------------------
# Initial hello handshake
# ---------------------------

class Hello(BaseModel):
    client_name: str
    timestamp: int


class ServerHello(BaseModel):
    server_name: str
    timestamp: int
    server_public_key: str  # base64-encoded


# ---------------------------
# User account operations
# ---------------------------

class Register(BaseModel):
    username: str
    password: str


class Login(BaseModel):
    username: str
    password: str


# ---------------------------
# Diffie-Hellman key exchange
# ---------------------------

class DHClient(BaseModel):
    dh_public: str  # base64-encoded client public key
    timestamp: int


class DHServer(BaseModel):
    dh_public: str  # base64-encoded server public key
    timestamp: int


# ---------------------------
# Chat message + signature
# ---------------------------

class Msg(BaseModel):
    sender: str
    ciphertext: str      # base64-encoded AES ciphertext
    iv: str              # base64-encoded initialization vector
    signature: str       # base64 signature of ciphertext
    timestamp: int


# ---------------------------
# Receipt (acknowledgment)
# ---------------------------

class Receipt(BaseModel):
    msg_id: str
    status: str           # "ok" or "error"
    timestamp: int
