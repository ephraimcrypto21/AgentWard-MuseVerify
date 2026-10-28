#!/usr/bin/env python3
"""FP-10: `assert` used only for internal invariants, not user validation."""
from dataclasses import dataclass


@dataclass
class Money:
    minor_units: int
    currency: str = "USD"

    def add(self, other):
        # Both operands are constructed by callers inside this package,
        # so `assert` is fine even under `python -O` for the demo binary.
        assert self.currency == other.currency
        return Money(self.minor_units + other.minor_units, self.currency)

    def scaled(self, factor):
        return Money(round(self.minor_units * factor), self.currency)

    def __str__(self):
        return f"{self.minor_units / 100:.2f} {self.currency}"


def total(items):
    acc = Money(0)
    for item in items:
        acc = acc.add(item)
    return acc


if __name__ == "__main__":
    print(total([Money(1250), Money(500)]))
