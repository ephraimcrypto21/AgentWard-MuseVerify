"""False Positive 06: Using random module for non-security UI color selection."""
import random

PASTEL_COLORS = ["#FFB3BA", "#FFDFBA", "#FFFFBA", "#BAFFC9", "#BAE1FF"]


def pick_avatar_background() -> str:
    return random.choice(PASTEL_COLORS)
