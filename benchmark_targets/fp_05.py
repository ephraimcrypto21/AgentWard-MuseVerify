"""False Positive 05: Sanitized HTML output using html.escape."""
import html


def render_greeting(user_name: str) -> str:
    safe_name = html.escape(user_name, quote=True)
    return f"<div class='greeting'>Hello, {safe_name}!</div>"
