# Protocol v3 deployment — 31 October 2026

The authorized Ubuntu verification node and workstation were upgraded together.
Application release: `166a7b6b65e4fe78fdd4d1161a0c880fd598e7e9`.
Both remote systemd services are enabled, active and running without restart
failures. The local dashboard was restarted and advertises all three languages.

## Installed configuration

- Full application checkout and isolated Python environment at
  `/home/ubuntu/agentward-node`. All `requirements-node.txt` dependencies were
  installed in the staged environment and `pip check` passed before switching.
- `agentward-sandbox:multilang-v3`, with Node **24.22.2**, Python **3.12.16** and
  strace. Remote image ID:
  `sha256:a966d3a4cb427bf3745a3b33ffd98e5d8647a3365b16ca6ee8709e28b56f0bfd`.
- Both services bind to loopback. Persistent Tailscale Serve TCP forwards expose
  ports 8000 and 8001 only within the existing private tailnet. The workstation
  uses these private endpoints; it no longer depends on temporary SSH forwards.
- A shared random node token is stored in root-owned mode-0600
  `/etc/agentward/node.env` and the workstation's ignored mode-0600 `.env`.
  No credentials or node addresses are included in this record.
- `.dockerignore` excludes the repository contents from the image build context.
  The image needs only its Dockerfile and upstream images; a virtual environment
  must not cause a multi-gigabyte context upload.

## Live acceptance

All **25 acceptance groups passed** against the actual authenticated remote
services over the private tailnet:

- Missing and invalid tokens were rejected across all eight ingress/sandbox
  aliases (16 requests).
- Python, JavaScript and TypeScript parsing/classification returned complete
  coverage, correct language identity and matching original/sanitized hashes.
  Positive ingress controls passed in all three languages.
- `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` and `.cts` executed inside Docker,
  with protocol-v3 evidence, matching source/harness hashes and protected traces.
- Mismatched request languages were rejected by both services.
- Python and JavaScript command-injection controls and a TypeScript SQL-injection
  control reproduced. Deterministic fixture repairs blocked them; the Node
  repairs also preserved normal results and triggered the canary tripwire.
- Python and Node payloads could not write protected traces, evidence directories,
  bootstrap files or the root filesystem, or regain UID 0. Payloads ran as UID
  65534 with no effective/permitted capabilities and `NoNewPrivs` enabled.
  The Python network-denial control also passed.
- The authenticated ingress-to-sandbox proxy executed TypeScript and returned
  protected protocol-v3 evidence.

The classifier loaded from the existing cached Prompt-Guard model. Short source
snippets, the JavaScript command benchmark and the benign Node benchmark can
produce **false-positive injection classifications**. The same behavior was
observed before the upgrade. Such inputs remain blocked; no thresholds or gates
were relaxed. A JavaScript version of the SQL benchmark passed ingress.

This validates the deployed node services and their workstation integration.
Repair candidates in these checks were fixtures; no live model-provider calls
or new seven-phase model-generated remediation claims are made.

Detailed evidence and the acceptance script are retained locally in the ignored
`reports/protocol-v3-remote-acceptance.json` and
`reports/protocol-v3-remote-acceptance.py`. The dashboard log is
`reports/dashboard-v3.log`.

## Rollback

The complete previous checkout, its local edits, logs and original Python
environment remain in
`/home/ubuntu/agentward-backups/pre-v3-166a7b6/app`. The previous systemd units
are saved alongside it. The old `agentward-sandbox:latest` image was retained.

Rollback requires stopping both services, disabling the two newly configured
Tailscale Serve forwards, restoring the previous application directory and unit
files, reloading systemd and restarting both services. Coordinate the workstation
rollback as well: the old node does not implement authentication or protocol v3
and must not be presented as a valid backend for the new workstation. Preserve
the deployed directory separately before restoring the backup.
