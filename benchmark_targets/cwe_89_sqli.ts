// Intentionally vulnerable benchmark. Repairs belong in patches/.
import {DatabaseSync} from 'node:sqlite';

export function lookup(user: string): unknown[] {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    return db.prepare("SELECT name FROM users WHERE name = '" + user + "'").all();
  } finally {
    db.close();
  }
}
