#!/usr/bin/env python3
"""
AgentWard Stage 3 - Pre-execution permission enforcement (ACP).

Reads a proposed tool-call payload (JSON) from stdin, as delivered by the
`PreToolUse` lifecycle hook, e.g.:

    {"toolCall": {"name": "run_command", "args": {"CommandLine": "ls -la"}}, ...}

Emits exactly one decision on stdout:

    {"decision": "deny", "reason": "[ACP] Blocked by AgentWard Policy"}
    {"decision": "allow"}

Design principles (zero-trust):
  * Fail closed: unparseable / unexpected input is denied.
  * Inspect every command-bearing string in the payload, not just one key.
  * Scan both the raw command and a de-obfuscated form (quotes, backslashes,
    and `$IFS`-style separators stripped) to defeat trivial evasion such as
    `r""m -r'f' /` or `rm${IFS}-rf`.
"""
import json
import re
import sys

DENY = '{"decision": "deny", "reason": "[ACP] Blocked by AgentWard Policy"}'
ALLOW = '{"decision": "allow"}'

# Argument keys whose values are executed as shell / process input.
# (File-content keys are intentionally excluded so that writing source code
# that merely *mentions* e.g. "rm -rf" is not blocked.)
COMMAND_KEYS = {"commandline", "command", "cmd", "input", "script", "args", "argv"}

_F = re.IGNORECASE

# --------------------------------------------------------------------------
# Destructive patterns
# --------------------------------------------------------------------------
DESTRUCTIVE_PATTERNS = [
    # rm with both recursive and force flags, any order / grouping:
    #   rm -rf, rm -fr, rm -Rf, rm -r -f, rm -f -r, rm --recursive --force
    re.compile(r"\brm\s+(?:-\S+\s+)*-[a-z]*r[a-z]*f[a-z]*\b", _F),
    re.compile(r"\brm\s+(?:-\S+\s+)*-[a-z]*f[a-z]*r[a-z]*\b", _F),
    re.compile(r"\brm\s+(?:\S+\s+)*?-[a-z]*r[a-z]*\s+(?:\S+\s+)*?-[a-z]*f", _F),
    re.compile(r"\brm\s+(?:\S+\s+)*?-[a-z]*f[a-z]*\s+(?:\S+\s+)*?-[a-z]*r", _F),
    re.compile(r"\brm\s+.*--recursive.*--force|\brm\s+.*--force.*--recursive", _F),
    # Recursive delete of root / home / wildcard even without -f
    re.compile(r"\brm\s+(?:-\S+\s+)*-[a-z]*r[a-z]*\s+(?:/|~|\$HOME|/\*|\*)(?:\s|$)", _F),
    # Filesystem / block-device destruction
    re.compile(r"\bmkfs(?:\.\w+)?\b", _F),
    re.compile(r"\bdd\b[^|;&]*\bof=/dev/(?:sd|hd|nvme|xvd|vd|disk|mmcblk)", _F),
    re.compile(r">\s*/dev/(?:sd|hd|nvme|xvd|vd|disk|mmcblk)\w*", _F),
    re.compile(r"\b(?:shred|wipefs)\b", _F),
    # Fork bomb
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    # Recursive permission / ownership clobbering of root
    re.compile(r"\bch(?:mod|own)\s+(?:-\S+\s+)*-[a-z]*R[a-z]*\s+\S+\s+/(?:\s|$)"),
    # find-based mass deletion
    re.compile(r"\bfind\b.*\s-delete\b", _F),
    re.compile(r"\bfind\b.*-exec\s+rm\b", _F),
    # Irrecoverable VCS history / workspace wipes
    re.compile(r"\bgit\s+clean\s+(?:-\S+\s+)*-[a-z]*f[a-z]*d|\bgit\s+clean\s+(?:-\S+\s+)*-[a-z]*d[a-z]*f", _F),
]

# --------------------------------------------------------------------------
# Exfiltration patterns
# --------------------------------------------------------------------------
# Hard canary: any reference to the protected key is denied outright.
PROTECTED_SECRET = re.compile(r"META_API_KEY", _F)

# Generic secret sources (env vars, env dumps, credential files).
SECRET_SOURCE = re.compile(
    r"(\$\{?[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)[A-Z0-9_]*\}?"
    r"|\bprintenv\b|\benv\b(?!\s*=)|\bset\b\s*(?:\||$)|\bexport\s+-p\b"
    r"|/proc/(?:self|\d+)/environ"
    r"|\bos\.environ\b|\bos\.getenv\b|\bprocess\.env\b|\bENV\[|\$env:"
    r"|(?:^|[\s/'\"])\.env(?:\.\w+)?\b"
    r"|\.ssh/(?:id_\w+|authorized_keys)|\.aws/credentials|\.netrc|\.git-credentials"
    r"|\.docker/config\.json|\.kube/config|/etc/shadow)",
    _F,
)

# Network egress channels.
EGRESS_SINK = re.compile(
    r"(\b(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|scp|sftp|rsync|ssh)\b"
    r"|/dev/(?:tcp|udp)/"
    r"|\bInvoke-WebRequest\b|\biwr\b|\bInvoke-RestMethod\b"
    r"|\b(?:requests|httpx|urllib|http\.client|socket|aiohttp)\b"
    r"|\bnslookup\b|\bdig\b|\bhost\s+\S+\.\S+"
    r"|https?://)",
    _F,
)


def _deobfuscate(cmd: str) -> str:
    """Collapse common shell obfuscation tricks into a canonical form."""
    s = re.sub(r"\$\{?IFS\}?", " ", cmd)          # rm${IFS}-rf
    s = s.replace("\\\n", "")                      # line continuations
    s = re.sub(r"[\"'`\\]", "", s)                 # r""m, r\m, 'rm'
    s = re.sub(r"\s+", " ", s)
    return s


def _collect_command_strings(obj, under_cmd_key=False, out=None):
    """Recursively gather strings stored under command-bearing keys."""
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            is_cmd = str(k).lower() in COMMAND_KEYS
            _collect_command_strings(v, under_cmd_key or is_cmd, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_command_strings(item, under_cmd_key, out)
    elif isinstance(obj, str) and under_cmd_key:
        out.append(obj)
    return out


def is_violation(cmd: str) -> bool:
    for candidate in (cmd, _deobfuscate(cmd)):
        if any(p.search(candidate) for p in DESTRUCTIVE_PATTERNS):
            return True
        if PROTECTED_SECRET.search(candidate):
            return True
        if SECRET_SOURCE.search(candidate) and EGRESS_SINK.search(candidate):
            return True
    return False


def evaluate(payload) -> str:
    if not isinstance(payload, dict):
        return DENY
    tool_call = payload.get("toolCall", payload)
    if not isinstance(tool_call, dict):
        return DENY
    args = tool_call.get("args", tool_call)

    # Accept either a structured args object or a bare command string.
    if isinstance(args, str):
        commands = [args]
    else:
        commands = _collect_command_strings(args)

    if any(is_violation(c) for c in commands):
        return DENY
    return ALLOW


def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
        decision = evaluate(payload)
    except Exception:
        decision = DENY  # fail closed
    sys.stdout.write(decision + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
