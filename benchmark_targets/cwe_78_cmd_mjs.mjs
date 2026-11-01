// Intentionally vulnerable benchmark. Repairs belong in patches/.
// CWE-78: untrusted input concatenated into a shell-interpreted command (ES module).
import {execSync} from 'node:child_process';

export function runDiagnostic(input) {
  return execSync('printf %s ' + input).toString();
}
