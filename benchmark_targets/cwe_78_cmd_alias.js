// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-78: aliased shell API reached through a template literal (CommonJS JavaScript).
const {execSync: runShell} = require('node:child_process');

function diagnostic(input) {
  return runShell(`printf %s ${input}`).toString();
}

module.exports = {diagnostic};
