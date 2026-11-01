// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-89: untrusted input concatenated into a SQL statement (CommonJS TypeScript).
const {DatabaseSync} = require('node:sqlite');

function lookup(user: string): unknown[] {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    return db.prepare("SELECT name FROM users WHERE name = '" + user + "'").all();
  } finally {
    db.close();
  }
}

module.exports = {lookup};
