#!/usr/bin/env python3
"""Install or verify the pinned skill collection with the Codex installer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def tree_digest(directory):
    """Hash relative paths and file bytes; reject symlinks and special files."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f'Not a regular skill directory: {directory.name}')
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'Symlink in skill: {directory.name}')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f'Special file in skill: {directory.name}')
        digest.update(path.relative_to(directory).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main():
    codex_dir = Path(os.getenv('CODEX_HOME', str(Path.home() / '.codex')))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'verify'])
    parser.add_argument('--dest', type=Path, default=codex_dir / 'skills')
    parser.add_argument('--installer', type=Path,
                        default=codex_dir / 'skills/.system/skill-installer/scripts/install-skill-from-github.py')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'security/skills.lock.json').read_text())
    missing = []
    for skill in lock['skills']:
        dest = args.dest / skill['name']
        if not dest.exists() and not dest.is_symlink():
            missing.append(skill)
        elif tree_digest(dest) != skill['tree_sha256']:
            raise ValueError(f'Installed skill differs from lock: {skill["name"]}; preserve local changes before reinstalling')
    if missing and args.action == 'install':
        subprocess.run([sys.executable, str(args.installer), '--repo', lock['repository'],
                        '--ref', lock['commit'], '--dest', str(args.dest), '--path',
                        *[s['path'] for s in missing]], check=True)
    for skill in lock['skills']:
        if tree_digest(args.dest / skill['name']) != skill['tree_sha256']:
            raise ValueError(f'Skill verification failed: {skill["name"]}')
    print(f'Verified {len(lock["skills"])} skills at {lock["commit"]}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
