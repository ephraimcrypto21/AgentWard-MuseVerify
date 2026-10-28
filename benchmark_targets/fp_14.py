#!/usr/bin/env python3
"""FP-14: file paths built with pathlib plus an explicit containment check."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / "uploads"


def _contained(candidate):
    try:
        candidate.resolve().relative_to(BASE_DIR.resolve())
        return True
    except ValueError:
        return False


def read_upload(name):
    """`..` traversal is rejected after resolution, not by string cleaning."""
    target = BASE_DIR / name
    if not _contained(target):
        raise ValueError(f"path escapes upload dir: {name}")
    return target.read_text(encoding="utf-8")


def write_upload(name, content):
    target = BASE_DIR / name
    if not _contained(target):
        raise ValueError(f"path escapes upload dir: {name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


if __name__ == "__main__":
    print(_contained(BASE_DIR / "../etc/passwd"))
