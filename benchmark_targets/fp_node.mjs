// Benign false-positive control: parameterized SQL and a non-shell argv array.
import {execFileSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';

export function lookupUser(input) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    return db.prepare('SELECT name FROM users WHERE name = ?').all(input);
  } finally {
    db.close();
  }
}

export function runCommand(input) {
  return execFileSync('echo', [input], { shell: false }).toString();
}
