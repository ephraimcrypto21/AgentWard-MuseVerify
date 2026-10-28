#!/usr/bin/env python3
"""FP-04: HTML rendered through a template engine with autoescaping enabled."""
from jinja2 import Environment, select_autoescape

# Autoescape is on for .html templates, so {{ comment }} is escaped and safe.
ENV = Environment(autoescape=select_autoescape(["html", "xml"]))

COMMENT_PAGE = ENV.from_string(
    "<section><h2>{{ title }}</h2><p>{{ comment }}</p></section>"
)


def render_comment(title, comment):
    """A raw `<script>` in the comment does not execute."""
    return COMMENT_PAGE.render(title=title, comment=comment)


def render_many(entries):
    return "\n".join(render_comment(e["title"], e["comment"]) for e in entries)


if __name__ == "__main__":
    print(render_comment("Hello", "<script>alert(1)</script>"))
