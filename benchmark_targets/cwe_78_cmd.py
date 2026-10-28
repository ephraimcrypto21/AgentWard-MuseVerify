#!/usr/bin/env python3
"""Benchmark target: CWE-78 OS Command Injection (reachable sink)."""
import os


def ping_host(host):
    """User controlled host is interpolated into a shell string."""
    command = f"ping -c 1 -W 1 {host}"
    return os.system(command)


def list_directory(path):
    """Same flaw through subprocess with a shell."""
    import subprocess

    return subprocess.run(f"ls -la {path}", shell=True, capture_output=True, text=True)


if __name__ == "__main__":
    # Benign input
    ping_host("127.0.0.1")
    print(list_directory("/tmp").stdout)
    # Exploit payload chains a second command
    ping_host("127.0.0.1; id")
