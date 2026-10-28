#!/usr/bin/env python3
"""FP-18: os.path.join plus a fixed suffix, no shell and no interpolation sink."""
import os

DATA_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ALLOWED_EXTENSIONS = {".csv", ".tsv", ".jsonl"}


def dataset_path(name):
    """Extension allow-list, then a join; the result is only read, never executed."""
    extension = os.path.splitext(name)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(f"unsupported dataset extension: {extension!r}")
    path = os.path.join(DATA_ROOT, name)
    if not os.path.abspath(path).startswith(DATA_ROOT + os.sep):
        raise ValueError(f"dataset escapes data root: {name}")
    return path


def list_datasets():
    if not os.path.isdir(DATA_ROOT):
        return []
    return sorted(
        entry
        for entry in os.listdir(DATA_ROOT)
        if os.path.splitext(entry)[1].lower() in ALLOWED_EXTENSIONS
    )


if __name__ == "__main__":
    print(list_datasets())
