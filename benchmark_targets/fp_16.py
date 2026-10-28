#!/usr/bin/env python3
"""FP-16: HTTP client pointed at a localhost service, so plain http is correct."""
import http.client
import json

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8081


def local_health():
    """Traffic never leaves the loopback interface; TLS would add nothing."""
    conn = http.client.HTTPConnection(LOCAL_HOST, LOCAL_PORT, timeout=2)
    try:
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        conn.close()


def local_submit(payload):
    conn = http.client.HTTPConnection(LOCAL_HOST, LOCAL_PORT, timeout=2)
    try:
        body = json.dumps(payload)
        conn.request("POST", "/jobs", body=body, headers={"Content-Type": "application/json"})
        return conn.getresponse().status
    finally:
        conn.close()


if __name__ == "__main__":
    print(local_submit({"kind": "noop"}))
