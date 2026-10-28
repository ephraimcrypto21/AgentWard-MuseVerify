import sqlite3
def safe_lookup(user_id):
    conn = sqlite3.connect("db.sqlite")
    # Parameterized query - Safe from SQLi
    return conn.cursor().execute("SELECT * FROM accounts WHERE id = ?", (user_id,)).fetchone()
