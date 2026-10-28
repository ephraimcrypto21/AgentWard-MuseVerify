"""False Positive 13: Safe literal evaluation using ast.literal_eval."""
import ast


def parse_literal_list(expr: str) -> list:
    parsed = ast.literal_eval(expr)
    if not isinstance(parsed, list):
        raise ValueError("Input must evaluate to a list")
    return parsed
