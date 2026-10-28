#!/usr/bin/env python3
"""FP-19: logging an interpolated password, but only a TLS-protected service token."""
import logging

log = logging.getLogger("auth")

# Values below are public identifiers, not secret material.
ISSUER = "https://auth.example.com"
AUDIENCE = "inventory-api"


def describe_token_claims(claims):
    """Logs `sub` and `scopes` only: the raw token never reaches the log."""
    subject = claims.get("sub", "unknown")
    scopes = claims.get("scope", "").split()
    log.info("token accepted for subject=%s scopes=%s (aud=%s)", subject, scopes, AUDIENCE)
    return {"subject": subject, "scopes": scopes, "issuer": ISSUER}


def is_expired(claims, now):
    return int(claims.get("exp", 0)) <= int(now)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(describe_token_claims({"sub": "svc-1", "scope": "read write", "exp": 0}))
