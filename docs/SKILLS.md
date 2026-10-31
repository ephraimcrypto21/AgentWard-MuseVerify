# Cybersecurity skill collection

On 31 October 2026, all **818** skills from the independent community repository
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
were installed into the local Codex skill directory. The collection is licensed
under Apache-2.0 and is not affiliated with Anthropic. Per-skill licenses and
supporting references/scripts were preserved.

The source revision is
`54a798831d2266a3ca61ce68a7acb80b81160d57`. Every installed skill's complete file
tree was compared with that revision. `security/skills.lock.json` records all
names, source paths, and SHA-256 tree digests. This proves byte identity to the
pinned source; it is not an assertion that all 818 procedures or scripts have
been audited or executed.

## Reproduce the installation

With Codex's built-in skill-installer available:

```bash
python3 tools/manage_cybersecurity_skills.py install
python3 tools/manage_cybersecurity_skills.py verify
```

`--dest` overrides the skill directory; `--installer` overrides the built-in
installer script location. `CODEX_HOME` is respected. Matching existing skills
are retained; conflicting local edits stop installation before new skills are
copied. Installation downloads the pinned revision, then verifies all trees.
No external skill scripts or their optional tool dependencies are run by this
installer. Skills become discoverable in Codex on the next turn.

To update the collection, deliberately review a new upstream commit, generate a
new inventory with `tree_digest`, compare the changes, and install/verify that
revision. Do not silently follow the moving upstream branch.

## Applied to this project

These procedures informed the implementation and architecture review. Their
recommendations were adapted to this harness; this table does not claim full
CIS compliance, a Threat Dragon application run, or use of every example tool.

| Skill | Application here | Evidence |
| --- | --- | --- |
| [securing-agentic-ai-tool-invocation](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/securing-agentic-ai-tool-invocation/SKILL.md) | Authenticated node calls, strict argument schema, bounded execution, existing mandatory policy gates | Service authentication/schema tests and Docker acceptance |
| [hardening-docker-containers-for-production](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hardening-docker-containers-for-production/SKILL.md) | Unprivileged payload, read-only root/inputs, bounded tmpfs, dropped payload capabilities, protected tracing | UID/capability, write-denial, network, overflow and timeout tests |
| [testing-websocket-api-security](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/testing-websocket-api-security/SKILL.md) | Origin validation before replay, connection cap, bounded messages and send deadlines | HTTP/WebSocket boundary tests and offline E2E |
| [testing-for-host-header-injection](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/testing-for-host-header-injection/SKILL.md) | Exact host allowlist independent of browser Origin; no trust in forwarded host | Host confusion and origin rejection tests |
| [performing-threat-modeling-with-owasp-threat-dragon](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-threat-modeling-with-owasp-threat-dragon/SKILL.md) | STRIDE inventory, data flows, explicit trust boundaries and residual risks | `docs/THREAT_MODEL.md` |

The application does not ingest all skill bodies as model instructions, execute
their scripts automatically, or treat their recommendations as runtime proof.
The collection supports scoped engineering and security reviews through Codex.
