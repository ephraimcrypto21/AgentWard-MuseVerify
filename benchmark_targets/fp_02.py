"""False Positive 02: Secure subprocess.run without shell=True."""
import subprocess


def list_directory_safe(path: str) -> str:
    result = subprocess.run(
        ["ls", "-la", path],
        shell=False,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout
