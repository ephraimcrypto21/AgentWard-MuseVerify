"""False Positive 17: URL validation restricting schemes to HTTPS only."""
from urllib.parse import urlparse


def validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Only valid HTTPS URLs are permitted")
    return url
