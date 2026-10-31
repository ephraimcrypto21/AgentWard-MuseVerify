import {execFileSync} from 'node:child_process';

export function runCommand(input) {
  return execFileSync('/usr/bin/printf', ['%s', input]).toString();
}
