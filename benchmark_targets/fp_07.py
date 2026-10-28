"""False Positive 07: Safe JSON configuration parsing."""
import json


def parse_config_json(raw_payload: str) -> dict:
    data = json.loads(raw_payload)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data
