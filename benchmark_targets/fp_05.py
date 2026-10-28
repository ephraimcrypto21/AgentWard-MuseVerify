#!/usr/bin/env python3
"""FP-05: eval/exec-free parsing via ast.literal_eval on trusted literals."""
import ast

DEFAULT_SETTINGS = "{'theme': 'dark', 'page_size': 25, 'show_sidebar': True}"


def parse_settings(raw):
    """literal_eval only accepts Python literals, so arbitrary code cannot run."""
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return {}
    if not isinstance(value, dict):
        return {}
    return value


def merge_with_defaults(raw):
    merged = {"theme": "light", "page_size": 50, "show_sidebar": False}
    merged.update({k: v for k, v in parse_settings(raw).items() if k in merged})
    return merged


if __name__ == "__main__":
    print(merge_with_defaults(DEFAULT_SETTINGS))
    print(merge_with_defaults("__import__('os').getcwd()"))
