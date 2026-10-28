#!/usr/bin/env python3
"""FP-20: JSON deserialized from a response and validated before attribute access."""
import json


class SchemaError(ValueError):
    """Raised when the payload does not match the expected contract."""


def _require(mapping, key, types, default=None):
    if key not in mapping:
        if default is not None:
            return default
        raise SchemaError(f"missing required key: {key}")
    value = mapping[key]
    if not isinstance(value, types):
        raise SchemaError(f"key {key!r} has type {type(value).__name__}")
    return value


def parse_invoice(raw):
    """Structure is checked explicitly; no eval, no attribute guessing."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SchemaError("payload must be a JSON object")

    invoice_id = _require(data, "id", str)
    lines = _require(data, "lines", list, default=[])
    clean_lines = []
    for line in lines:
        if not isinstance(line, dict):
            raise SchemaError("each line must be an object")
        clean_lines.append(
            {
                "description": _require(line, "description", str),
                "amount": _require(line, "amount", (int, float)),
            }
        )
    return {"id": invoice_id, "lines": clean_lines}


if __name__ == "__main__":
    print(parse_invoice('{"id": "INV-1", "lines": [{"description": "hosting", "amount": 12.5}]}'))
