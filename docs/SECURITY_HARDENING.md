# Security hardening verification — 31 October 2026

This record describes the protocol-v2 hardening release. The subsequent
[language-adapter change](LANGUAGES.md) introduces protocol v3 and a Python/Node
image; use its deployment instructions for the current checkout.

This change strengthens the existing seven-phase harness using the cybersecurity
skills described in `SKILLS.md`. Meta remains mandatory for live verification.

## Changes verified

- All 818 skills were installed with Codex's skill-installer from upstream commit
  `54a798831d2266a3ca61ce68a7acb80b81160d57`. Every installed file tree matches its
  source tree and the committed SHA-256 inventory.
- HTTP and WebSocket requests reject untrusted hosts/origins before controls or
  telemetry are served. Connection, message, replay-write and body limits were added.
- Classifier and sandbox execution aliases require the shared node bearer token.
  Requests have bounded schemas and immediate saturation rejection. Node clients
  reject redirects and ignore ambient proxies.
- Ingress responses bind both original and sanitized source bytes. Sandbox
  protocol v2 requires protected traces and original source/harness hashes.
- The sandbox separates the root tracer from UID/GID 65534 payload execution.
  The payload has no effective/permitted capabilities, cannot change root UID,
  cannot modify/read the protected trace, cannot write host-backed evidence files,
  and cannot change the read-only root, input files, or bootstrap.
- Output overflow and timeouts remove the container and deny evidence. The trace
  parser preserves one event beyond the cap so truncation cannot appear complete.
- The threat model, contributor rules, reproducible skill verifier, deployment
  migration instructions, and GitHub Actions verification workflow were added.
- The pre-existing project-guide PDF was included, labeled as an earlier guide.

## Executed checks

| Check | Result |
| --- | --- |
| Full suite with `AGENTWARD_TEST_DOCKER=1 SANDBOX_IMAGE=agentward-sandbox:security-v2 python -m unittest discover -v` | **63 tests passed**, including five real Docker acceptance tests; no skips |
| Real Docker isolation | Evidence-write/unlink/replace attempts, host evidence disk writes, tracer FD access, tracer kill, root/bootstrap/input writes, UID escalation and network attempts rejected |
| Python startup isolation | A submitted `sitecustomize.py` executes only after dropping to UID 65534 |
| Behavioral preservation | Original SQL injection reproduced; repaired source blocks the exploit using the real Docker/strace backend |
| Output/time/trace exhaustion | Bounded failures; no new running containers left behind |
| Real HTTP/WebSocket offline E2E | Three `SIMULATED_REMEDIATION` outcomes and one `SIMULATED_FALSE_POSITIVE`; all seven phases, 281 telemetry events |
| Skill installation integrity | 818 complete trees verified against the pinned source and lock |
| Ruff correctness/import checks | Passed |
| `python -m pip check` | Passed |
| `bash -n deploy_remote_services.sh` and `git diff --check` | Passed |

Local validation used Python 3.14.8 and Docker 28.5.2. The sandbox image was built
from the locally available `python:3.12-slim` base with Debian strace installed.
CI runs on Python 3.12, builds its own sandbox image, and executes the same Docker
acceptance suite. GitHub Actions are pinned to verified commit IDs. The sandbox
base tag and Python dependency ranges are still mutable; image/dependency signing
and a fully locked production build remain future supply-chain work.

## Deployment scope

These results cover local code, real local Docker execution, and an offline
dashboard run with deterministic model fixtures. The remote node and live model
providers were not redeployed or revalidated as part of this change. The historical
30 October live results in `VERIFICATION.md` apply to the previous protocol.

Before running this version against the remote node, deploy both updated services
and their shared `service_security.py` / `sandbox_protocol.py` modules, provision
the same random `AGENTWARD_NODE_TOKEN` on the workstation and node, and restart
them together. The deployment script creates and preserves the node's root-only
token file. Clients reject stale nodes. Re-run live acceptance after upgrading.

The sandbox requires rootful Linux Docker without user-namespace remapping and
POSIX ACL support. A shared token and loopback dashboard are suitable for this
single-operator architecture; multi-user identity, signed audit storage and
transport-level rate limiting require additional design. The explicit residual
risks and ownership are recorded in `THREAT_MODEL.md`.
