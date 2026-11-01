// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-338: predictable reset token from Math.random alongside a bound SQL lookup.
const {DatabaseSync} = require('node:sqlite');

function generateResetToken(input) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    const rows = db.prepare('SELECT name FROM users WHERE name = ?').all(input);
    const token = Math.random().toString(16).slice(2);
    return {allowlisted: rows.length > 0, hasToken: token.length > 0};
  } finally {
    db.close();
  }
}

module.exports = {generateResetToken};
