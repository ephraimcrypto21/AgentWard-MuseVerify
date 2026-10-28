#!/usr/bin/env python3
"""Benchmark target: CWE-89 SQL Injection (reachable sink)."""
import sqlite3

DB_PATH = "inventory.db"


def _connect():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = _connect()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, sku TEXT)"
    )
    conn.commit()
    conn.close()


def search_products(name_fragment):
    """Builds the query with an f-string, so user input lands straight in SQL."""
    conn = _connect()
    cursor = conn.cursor()
    query = f"SELECT id, name, sku FROM products WHERE name LIKE '%{name_fragment}%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_db()
    # Benign input
    print(search_products("widget"))
    # Exploit payload breaks out of the quoted string
    print(search_products("' OR '1'='1"))
