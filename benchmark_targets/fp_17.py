#!/usr/bin/env python3
"""FP-17: regex compiled once at import, and a literal-string swap."""
import re

_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_TOKEN = re.compile(r"[A-Za-z0-9._~-]{8,256}\Z")

REDACTIONS = (
    ("Bearer ", "Bearer [redacted]"),
    ("Basic ", "Basic [redacted]"),
)


def valid_header_name(name):
    return bool(_HEADER.fullmatch(name))


def valid_token_shape(token):
    """Shape check only; signature verification happens downstream."""
    return bool(_TOKEN.fullmatch(token))


def redact_authorization(value):
    for prefix, replacement in REDACTIONS:
        if value.startswith(prefix):
            return replacement
    return value


if __name__ == "__main__":
    print(valid_header_name("X-Request-Id"), valid_token_shape("abc123DEF456"))
