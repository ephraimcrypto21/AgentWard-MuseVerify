"""False Positive 15: Subprocess execution with static constant argument list."""
import subprocess


def get_git_revision() -> str:
    res = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        shell=False,
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip()
