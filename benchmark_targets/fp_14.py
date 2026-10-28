"""False Positive 14: Strict allowlist validation for sort column names."""
import sqlite3

ALLOWED_SORT_COLUMNS = {"created_at", "username", "id"}


def fetch_sorted_users(db_path: str, sort_by: str) -> list:
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise ValueError("Invalid sort column")
    query = f"SELECT id, username, created_at FROM users ORDER BY {sort_by} ASC"
    with sqlite3.connect(db_path) as conn:
        return conn.execute(query).fetchall()
