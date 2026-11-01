// Benign false-positive control (TypeScript ES module): erasable types only.
import {execFileSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {basename} from 'node:path';

interface Row {
  name: string;
}

type QueryResult<T> = T[];

export function lookupUser(input: string): QueryResult<Row> {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT); INSERT INTO users VALUES('agentward_normal')");
    return db.prepare('SELECT name FROM users WHERE name = ?').all(input) as Row[];
  } finally {
    db.close();
  }
}

export function runSafeCommand(input: string): string {
  const safeName: string = basename(input);
  return execFileSync('echo', [safeName], { shell: false }).toString();
}
