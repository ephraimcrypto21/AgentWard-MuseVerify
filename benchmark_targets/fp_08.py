"""False Positive 08: Safe file path resolution preventing path traversal."""
import os


def read_safe_template(base_dir: str, filename: str) -> str:
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(os.path.join(base_abs, filename))
    if os.path.commonpath([base_abs, target_abs]) != base_abs:
        raise PermissionError("Path traversal attempt blocked")
    with open(target_abs, "r", encoding="utf-8") as handle:
        return handle.read()
