// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-78: host argument concatenated into a shell command (CommonJS TypeScript).
const {execSync} = require('node:child_process');

function pingHost(host: string): string {
  return execSync('ping -c 1 -W 1 ' + host).toString();
}

module.exports = {pingHost};
