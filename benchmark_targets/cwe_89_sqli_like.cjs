// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-89: untrusted input concatenated into a LIKE pattern (CommonJS JavaScript).
const {DatabaseSync} = require('node:sqlite');

function searchProducts(nameFragment) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE products(name TEXT); INSERT INTO products VALUES('agentward_normal')");
    return db.prepare("SELECT name FROM products WHERE name LIKE '%" + nameFragment + "%'").all();
  } finally {
    db.close();
  }
}

module.exports = {searchProducts};
