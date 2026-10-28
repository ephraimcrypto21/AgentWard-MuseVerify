#!/usr/bin/env python3
"""FP-13: broad `except Exception`, but the exception is logged and handled."""
import logging

log = logging.getLogger(__name__)


class UpstreamUnavailable(RuntimeError):
    """Raised when all retries against the upstream provider fail."""


def fetch_profile(client, user_id, retries=3):
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            return client.get(f"/users/{user_id}")
        except Exception as exc:  # transport errors of many shapes
            last_error = exc
            log.warning("profile fetch failed (attempt %d/%d): %s", attempt, retries, exc)
    raise UpstreamUnavailable(f"could not fetch profile for {user_id}") from last_error


def safe_len(value):
    try:
        return len(value)
    except Exception:
        return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(safe_len(None), safe_len([1, 2]))
