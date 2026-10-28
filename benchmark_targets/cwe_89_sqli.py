"""Educational CWE-89 SQL Injection test case for static analysis benchmarking."""
import sqlite3


def get_user_by_username(db_path: str, username: str) -> list:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # CWE-89: Unsanitized string concatenation in SQL query
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results
