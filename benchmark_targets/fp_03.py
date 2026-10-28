#!/usr/bin/env python3
"""FP-03: subprocess.run with an argv list and no shell, so no metacharacter risk."""
import subprocess


def compress(input_path, output_path):
    """`tar czf` built as a list: user input stays a single argv element."""
    return subprocess.run(
        ["tar", "-czf", output_path, input_path],
        check=True,
        capture_output=True,
        text=True,
    )


def count_lines(path):
    result = subprocess.run(
        ["wc", "-l", path],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return int(result.stdout.split()[0])


def git_revision(repo_dir):
    result = subprocess.run(
        ["git", "-C", repo_dir, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if __name__ == "__main__":
    print(git_revision("."))
