"""Educational CWE-338 Weak PRNG test case for static analysis benchmarking."""
import random
import string


def generate_reset_token(length: int = 16) -> str:
    # CWE-338: Using standard random module for security-sensitive token generation
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))
