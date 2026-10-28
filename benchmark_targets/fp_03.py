"""False Positive 03: Cryptographically secure token generation using secrets."""
import secrets


def create_session_token() -> str:
    return secrets.token_urlsafe(32)
