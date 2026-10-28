"""False Positive 01: Parameterized sqlite3 query."""
import sqlite3


def get_user_safe(db_path: str, username: str) -> list:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        return cursor.fetchall()
