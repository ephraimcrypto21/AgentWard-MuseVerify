#!/usr/bin/env python3
"""FP-09: YAML parsed with safe_load instead of the unsafe full loader."""
from pathlib import Path

import yaml

DEFAULT_WORKFLOW = """
name: nightly
steps:
  - lint
  - test
"""


def parse_workflow(text):
    """safe_load never instantiates arbitrary Python objects."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return {}
    data.setdefault("steps", [])
    return data


def load_workflow(path):
    return parse_workflow(Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    print(parse_workflow(DEFAULT_WORKFLOW))
