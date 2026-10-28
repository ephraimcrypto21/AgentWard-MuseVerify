#!/usr/bin/env python3
"""FP-02: parameterized SQL query (placeholders, not string interpolation)."""
import sqlite3

DB_PATH = ":memory:"


def fetch_user_by_email(email):
    """Looks like the classic sink, but the value is bound by the driver."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, display_name FROM users WHERE email = ?",
            (email,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def fetch_users_by_role(role, active_only=True):
    query = "SELECT id, email FROM users WHERE role = ?"
    if active_only:
        query += " AND active = ?"
        params = (role, 1)
    else:
        params = (role,)
    conn = sqlite3.connect(DB_PATH)
    try:
        return conn.cursor().execute(query, params).fetchall()
    finally:
        conn.close()


if __name__ == "__main__":
    print(fetch_users_by_role("admin"))
