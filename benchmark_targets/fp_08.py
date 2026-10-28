#!/usr/bin/env python3
"""FP-08: `random` used for simulation and sampling, not for secrets."""
import random

POPULATION = [f"node-{i:02d}" for i in range(50)]


def sample_servers(k=5, seed=None):
    """Reproducibility matters more than unpredictability here."""
    rng = random.Random(seed)
    return rng.sample(POPULATION, min(k, len(POPULATION)))


def jittered_delay(base_ms=100, spread_ms=25):
    return base_ms + random.uniform(-spread_ms, spread_ms)


def simulate_latency(n=10, seed=7):
    rng = random.Random(seed)
    return [round(rng.gauss(120, 15), 2) for _ in range(n)]


if __name__ == "__main__":
    print(sample_servers(seed=1))
    print(simulate_latency())
