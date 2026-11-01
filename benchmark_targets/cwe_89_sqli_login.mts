// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-89: auth-bypass style lookup built by string interpolation (TypeScript ES module).
import {DatabaseSync} from 'node:sqlite';

interface Credentials {
  name: string;
  role: string;
}

type Rows<T> = T[];

export function authenticate(input: string): Rows<Credentials> {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(name TEXT, role TEXT); INSERT INTO users VALUES('agentward_normal','user')");
    return db.prepare("SELECT name, role FROM users WHERE name = '" + input + "' AND role = 'user'").all() as Rows<Credentials>;
  } finally {
    db.close();
  }
}
