"""False Positive 10: Safe integer parsing before SQL pagination."""
import sqlite3


def list_items_paginated(db_path: str, limit: int, offset: int) -> list:
    safe_limit = max(1, min(int(limit), 100))
    safe_offset = max(0, int(offset))
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name FROM items LIMIT ? OFFSET ?",
            (safe_limit, safe_offset),
        )
        return cursor.fetchall()
