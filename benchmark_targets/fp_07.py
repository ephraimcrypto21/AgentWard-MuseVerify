#!/usr/bin/env python3
"""FP-07: pickle.load of a locally produced, trusted cache file."""
import os
import pickle

CACHE_PATH = os.path.expanduser("~/.cache/metrics.pkl")


def load_cache():
    """The file is written by this same process, so unpickling is acceptable."""
    if not os.path.exists(CACHE_PATH):
        return {}
    with open(CACHE_PATH, "rb") as handle:
        return pickle.load(handle)


def save_cache(data):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "wb") as handle:
        pickle.dump(data, handle, protocol=pickle.HIGHEST_PROTOCOL)


def record(metric, value):
    data = load_cache()
    data.setdefault("samples", []).append({"metric": metric, "value": value})
    save_cache(data)
    return len(data["samples"])


if __name__ == "__main__":
    print(record("latency_ms", 42))
