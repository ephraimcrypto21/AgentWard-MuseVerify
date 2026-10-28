"""False Positive 09: Strong SHA-256 hashing for file integrity verification."""
import hashlib


def compute_sha256(content: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(content)
    return digest.hexdigest()
