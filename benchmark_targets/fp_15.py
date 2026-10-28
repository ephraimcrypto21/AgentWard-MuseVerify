#!/usr/bin/env python3
"""FP-15: requests call without TLS verification being disabled."""
import json

import requests

TIMEOUT = (3.05, 10)


def get_status(url):
    """verify=True is the default, but it is stated explicitly for reviewers."""
    response = requests.get(url, timeout=TIMEOUT, verify=True)
    response.raise_for_status()
    return response.status_code


def post_event(url, payload, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(
        url,
        data=json.dumps(payload),
        headers=headers,
        timeout=TIMEOUT,
        verify=True,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    print(get_status("https://example.com"))
