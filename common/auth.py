import base64
import hashlib
import os
import secrets


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return base64.b64encode(salt + dk).decode()


def verify_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored)
    salt, dk = raw[:16], raw[16:]
    new_dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return new_dk == dk


def generate_session_token() -> str:
    return secrets.token_urlsafe(64)
