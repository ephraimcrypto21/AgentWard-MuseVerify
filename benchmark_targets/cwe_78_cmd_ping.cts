// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-78: host argument concatenated into a shell command (CommonJS TypeScript).
// Echo the diagnostic host without requiring ping, DNS or network access.
const {execSync} = require('node:child_process');

function pingHost(host: string): string {
  return execSync('printf %s ' + host).toString();
}

module.exports = {pingHost};
