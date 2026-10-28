#!/usr/bin/env python3
"""FP-06: MD5 used as a non-cryptographic content checksum."""
import hashlib


def checksum_bytes(payload):
    """Integrity only: no secret, no attacker-controlled collision target."""
    return hashlib.md5(payload).hexdigest()


def checksum_file(path, chunk_size=65536):
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest(paths):
    return {p: checksum_file(p) for p in paths}


if __name__ == "__main__":
    print(checksum_bytes(b"release-artifact"))
