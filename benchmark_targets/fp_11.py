#!/usr/bin/env python3
"""FP-11: `eval` replaced by a small, locked-down expression evaluator."""
import operator
import re

_OPS = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "/": operator.truediv,
}
_TOKEN = re.compile(r"\s*(\d+(?:\.\d+)?|[-+*/])\s*")


def tokenize(expression):
    tokens = []
    pos = 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        if not match:
            raise ValueError(f"bad token at {pos}: {expression[pos:pos + 8]!r}")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


def evaluate(expression):
    """Single-pass left-to-right arithmetic; far safer than eval()."""
    tokens = tokenize(expression)
    if not tokens:
        raise ValueError("empty expression")
    value = float(tokens[0])
    for i in range(1, len(tokens) - 1, 2):
        op, operand = tokens[i], float(tokens[i + 1])
        value = _OPS[op](value, operand)
    return value


if __name__ == "__main__":
    print(evaluate("2 + 3 * 4 - 5"))
