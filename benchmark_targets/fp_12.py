"""False Positive 12: Constant-time string comparison for MAC verification."""
import hmac


def verify_signature(expected_sig: str, provided_sig: str) -> bool:
    return hmac.compare_digest(expected_sig.encode("utf-8"), provided_sig.encode("utf-8"))
