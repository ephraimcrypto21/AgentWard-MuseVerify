"""Educational CWE-78 OS Command Injection test case for static analysis benchmarking."""
import os


def ping_host(hostname: str) -> int:
    # CWE-78: Unsanitized user input passed directly to os.system
    command = "ping -c 1 " + hostname
    return os.system(command)
