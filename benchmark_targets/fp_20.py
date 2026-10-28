"""False Positive 20: Password hashing with PBKDF2-HMAC-SHA256."""
import hashlib
import os


def hash_password(password: str) -> tuple[bytes, bytes]:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt, derived
