# Instead of pymysql, use sqlite3
import sqlite3
from hashlib import sha256
import os
from app.common.utils import now_ms

DB_PATH = "users.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        password_hash BLOB NOT NULL,
        created_at INTEGER NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str, salt: bytes) -> bytes:
    return sha256(salt + password.encode("utf-8")).digest()

def create_user(username: str, password: str) -> bool:
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, salt, password_hash, created_at) VALUES (?,?,?,?)",
            (username, salt, pwd_hash, now_ms())
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username: str, password: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT salt, password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    salt, stored_hash = row
    return stored_hash == hash_password(password, salt)
