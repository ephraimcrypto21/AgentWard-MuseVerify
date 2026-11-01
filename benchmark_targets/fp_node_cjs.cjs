// Benign false-positive control (CommonJS): bound-parameter SQL and safe randomness.
const {DatabaseSync} = require('node:sqlite');
const {randomBytes} = require('node:crypto');

function lookupAllowlisted(input) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    return db.prepare('SELECT name FROM users WHERE name = ?').all(input);
  } finally {
    db.close();
  }
}

function mintToken(input) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    const rows = db.prepare('SELECT name FROM users WHERE name = ?').all(input);
    const token = randomBytes(16).toString('hex');
    return {allowlisted: rows.length > 0, tokenBytes: token.length};
  } finally {
    db.close();
  }
}

module.exports = {lookupAllowlisted, mintToken};
