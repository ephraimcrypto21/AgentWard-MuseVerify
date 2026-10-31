// Intentionally vulnerable benchmark. Repairs belong in patches/.
const {execSync} = require('node:child_process');

function runCommand(input) {
  return execSync('printf %s ' + input).toString();
}

module.exports = {runCommand};
