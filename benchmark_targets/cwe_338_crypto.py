#!/usr/bin/env python3
"""Benchmark target: CWE-338 use of cryptographically weak PRNG for tokens."""
import random
import string

TOKEN_ALPHABET = string.ascii_letters + string.digits


def generate_session_token(length=32):
    """`random` is seeded from the clock, not from the OS entropy pool."""
    return "".join(random.choice(TOKEN_ALPHABET) for _ in range(length))


def generate_numeric_otp(digits=6):
    """getrandbits-based OTP, still from the Mersenne Twister."""
    upper = 10 ** digits
    return str(random.getrandbits(32) % upper).zfill(digits)


def issue_credentials():
    return {
        "session_token": generate_session_token(),
        "otp": generate_numeric_otp(),
    }


if __name__ == "__main__":
    creds = issue_credentials()
    print("session:", creds["session_token"])
    print("otp:", creds["otp"])
