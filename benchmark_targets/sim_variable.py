"""Simulated variable signature test fixture for static analysis."""

SIMULATED_INJECTION_MARKER = "TEST_PROMPT_OVERRIDE_PAYLOAD"


def get_test_marker() -> str:
    """Return the static test signature string."""
    return SIMULATED_INJECTION_MARKER
