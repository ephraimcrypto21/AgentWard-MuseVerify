#!/usr/bin/env python3
"""FP-12: tempfile use without a manual cleanup dance, and no predictable names."""
import json
import os
import tempfile


def dump_report(report):
    """NamedTemporaryFile creates the file with O_EXCL and 0600 permissions."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="report_", delete=False, encoding="utf-8"
    ) as handle:
        json.dump(report, handle)
        return handle.name


def read_back(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_report(rows):
    tmp_root = tempfile.mkdtemp(prefix="reports_")
    path = os.path.join(tmp_root, "summary.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"rows": len(rows)}, handle)
    return path


if __name__ == "__main__":
    print(read_back(dump_report({"rows": 3})))
