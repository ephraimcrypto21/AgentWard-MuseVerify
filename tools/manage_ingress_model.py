#!/usr/bin/env python3
"""Explicitly provision or verify the pinned ingress model; never fetch at inference."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingress_guard import MODEL_LOCK, verified_files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'verify'))
    args = parser.parse_args()
    from huggingface_hub import snapshot_download
    snapshot = snapshot_download(MODEL_LOCK['model_id'], revision=MODEL_LOCK['revision'],
                                 allow_patterns=list(MODEL_LOCK['files_sha256']),
                                 local_files_only=args.action == 'verify', max_workers=2)
    verified_files(snapshot)
    print(f"Verified {len(MODEL_LOCK['files_sha256'])} pinned ingress artifacts: {MODEL_LOCK['model_id']}@{MODEL_LOCK['revision']}")


if __name__ == '__main__':
    main()
