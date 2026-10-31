# AgentWard + MuseVerify

A Meta-primary security harness for evidence-driven repair of Python and single-file JavaScript/TypeScript Node modules. It inspects poisoned source, reproduces benchmark vulnerabilities in an authenticated Docker/strace sandbox, generates candidate repairs, and verifies them through independent model review, CodeShield, adversarial replay and regression tests.

**Meta remains mandatory on every live run.** `muse-spark-1.3` leads runtime policy checks and patch synthesis; `muse-wonder-1.0` leads deep semantic analysis. Verified Anti-Gravity and custom BYOK models can join as independent reviewers. Missing security evidence produces a blocked, rejected or inconclusive result.

The architecture now separates operator controls, model advice, untrusted payloads,
and protected verification evidence. The [threat model](docs/THREAT_MODEL.md)
defines those boundaries and their limits. All **818 cybersecurity skills** from
the requested community collection are installed locally and pinned with full-tree
hashes; see [skill provenance and usage](docs/SKILLS.md). The skills guide engineering
reviews while the application enforces its own mandatory runtime gates.

## Supported languages

| Language | Extensions | Verification scope |
| --- | --- | --- |
| Python | `.py` | Existing Python parsing, graph analysis and benchmark probes |
| JavaScript | `.js`, `.mjs`, `.cjs` | Node.js CommonJS/ES modules; exported single-argument SQL/command functions |
| TypeScript | `.ts`, `.mts`, `.cts` | Same Node probes; erasable TypeScript syntax, AST type erasure for scanning, original source executed by Node 24 |

Other extensions return `UNSUPPORTED_LANGUAGE`. A supported language with no
compatible probe entry points returns `UNSUPPORTED_TARGET`; syntax errors return
`INVALID_SOURCE`. Missing dependencies or execution evidence cannot become a
verified result. See [adapter behavior and limits](docs/LANGUAGES.md).

## Seven phases

| Phase | Responsibility | Required evidence |
| --- | --- | --- |
| 1 — Ingress Shield | Classify complete source with the pinned ingress model and parser context; sanitize injected instructions | Full source coverage, sanitizer rescan, model/policy identity and artifact hashes |
| 2 — Syscall Sandbox | Execute deterministic exploit probes in an isolated workspace | Docker execution, kernel strace events and completed behavioral probes |
| 3 — Runtime Hooks | Regex/entropy screening, unanimous ensemble policy review and trajectory monitoring | Valid votes; current operator policy; denial triggers workspace rewind |
| 4 — Patch Verification | Spark synthesis, API-contract checks, cross-file analysis, independent reviewers, CodeShield and structural tripwire validation | Every applicable gate passes |
| 4.5 — Adversarial Self-Play | Replay mutated and multi-step scenarios against original and candidate code | Positive controls on original code, no surviving exploit and valid sandbox evidence |
| 5 — Regression | Replay original exploit, normal inputs and decoy guards | Exploit blocked, functional checks pass, tripwire fires only for decoy probes |
| 5.1 — Semantic Hunter | Wonder-led multi-provider analysis of imported helpers and related modules | Static paths, model findings and coverage limits reported separately from runtime proof |

Phase 2 overlaps with AST graph construction and the Stage 3 policy baseline. At most three pipeline containers execute concurrently. A successful baseline cannot substitute for later sandbox or patch evidence.

Phase 4 receives the already observed ingress, original sandbox and runtime-policy
results. Its model votes approve only the candidate's static review. CodeShield,
adversarial replay and regression remain required before final remediation. The
review contract distinguishes the required decoy tripwire from injected source
instructions and separates unchanged, unrelated sibling findings from risks that
affect the selected target.

## Quick start

Python 3.12+ is recommended. The local development environment uses `venv/`.

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
# Populate Meta credentials and any optional providers in .env.
python -m uvicorn dashboard:app --host 127.0.0.1 --port 8080 --ws-max-size 1024 --ws-max-queue 4
```

Open [the dashboard](http://127.0.0.1:8080). The header shows the real provider pre-flight matrix. Select an ensemble, retest credentials, launch an audit, or add an operator restriction while a run is in progress.

The dashboard includes all seven phase cards, replayable WebSocket telemetry, a unified/side-by-side verified diff viewer, the executive brief, a cross-file call/taint map and SARIF export. HTTP and WebSocket routes validate exact allowed hosts and browser origins before serving data or replaying telemetry. Defaults accept `localhost`, `127.0.0.1`, and `::1`; set `DASHBOARD_ALLOWED_HOSTS` to a comma-separated list of exact names for an authenticated reverse proxy. Keep the dashboard on loopback or behind authenticated access controls. Native clients may omit Origin; these browser controls do not replace network access restrictions.

CLI entry points use the same orchestrator:

```bash
python main_pipeline.py poisoned_app.py
python main_pipeline.py benchmark_targets/cwe_78_cmd.js
python main_pipeline.py benchmark_targets/cwe_89_sqli.ts
python main_pipeline.py benchmark_targets
```

Original benchmark targets remain intentionally vulnerable. Accepted candidate patches and exact diffs are written under `patches/<run-id>/`; the harness does not silently overwrite the benchmark corpus.

## Providers and ensembles

| Mode | Participants |
| --- | --- |
| `auto` (default) | Meta primary + every healthy secondary |
| `all_three` | Meta + Anti-Gravity + Custom; explicit notices if a secondary is unavailable |
| `meta_plus_agy` | Meta + verified Anti-Gravity |
| `meta_plus_custom` | Meta + verified Custom BYOK |
| `meta_only` | Spark + Wonder cross-checking each other |

When no requested secondary passes pre-flight, Meta's other native model supplies the independent review. If Meta is offline, the run cannot proceed. Once selected, an unavailable or malformed reviewer response denies that review rather than becoming an implicit approval.

`discover_and_verify_providers(force_refresh=False)` probes providers concurrently, shares in-flight discovery requests and caches dashboard results for 60 seconds. Each run retains its successful pre-flight snapshot while credentials/configuration remain unchanged; task errors still deny approval. A forced refresh reloads `.env`.

| Configuration | Purpose |
| --- | --- |
| `META_API_KEY` | Required Meta credential |
| `META_API_BASE_URL` | Defaults to `https://api.meta.ai/v1` |
| `ENSEMBLE_MODE` | One of the five modes above |
| `AGY_BIN` | Optional explicit CLI path; otherwise PATH and `~/.local/bin/agy` |
| `AGY_SELECTED_MODEL` | Preferred high-end model, default `gemini-4-argon` |
| `AGY_PREFLIGHT_TIMEOUT_S` | Per-model probe deadline, capped at 30 seconds |
| `CUSTOM_API_URL` | Full Responses or Chat Completions endpoint, or `/v1` base |
| `CUSTOM_API_KEY` | Optional BYOK credential; empty/placeholder values never receive pipeline tasks |
| `CUSTOM_MODEL_NAME` | Model identifier supported by your chosen BYOK endpoint |
| `CUSTOM_REASONING_EFFORT` | Optional model-specific reasoning setting, where supported; default `medium` |
| `CUSTOM_SERVICE_TIER` | Optional `fast` / `ultrafast`, only where the endpoint supports it |
| `AI_TIMEOUT_S`, `AGY_TIMEOUT_S` | Bounded task deadlines |

Anti-Gravity tries the selected high-end model, then the deduplicated cascade `gemini-4-argon`, `claude-opus-5-5`, `claude-sonnet-5.5`, `gemini-3.8`. Quota failures are recorded. CLIs with `--max-turns` use a one-turn probe; this deployment's CLI instead uses bounded single-print mode. No permission-bypass flags are used.

Custom pre-flight has a five-second deadline and requires HTTP 200 with nonempty, complete content. Authentication failures, missing endpoints, timeouts and placeholder configuration exclude the provider without breaking discovery. Credentials are never returned by `/api/providers`.

## Remote ingress guard and sandbox node

Use an Ubuntu host with Docker and the dependencies in `requirements-node.txt`.
Ingress uses the pinned `Horizon-Labs/prompt-injection-guard-small` model with
bounded parser context and complete source coverage. The model runs locally;
its five artifacts are hash-verified before loading. Unavailable or changed
weights fail closed. See [ingress guard validation](docs/INGRESS_GUARD.md).

Deploy the full checkout to `/home/ubuntu/agentward-node/`, then run the deployment script there with sudo. Include `ingress_guard.py`, `security/ingress-model.lock.json` and the shared language, protocol, security and sanitizer modules. The script installs node dependencies, provisions and verifies the pinned model, builds `agentward-sandbox:multilang-v3` with Python, Node 24 and strace, and installs both systemd services. Both bind to `127.0.0.1`. The sandbox requires rootful Linux Docker without user-namespace remapping and a temporary filesystem supporting POSIX ACLs.

The deployment script creates `/etc/agentward/node.env` with a random token and
root-only permissions on first installation; subsequent deployments preserve it.
Securely copy the same `AGENTWARD_NODE_TOKEN` value into the workstation `.env`,
then restart the dashboard. A missing/short node token returns HTTP 503; an absent
or incorrect bearer token returns 401. All classifier and execution aliases
require authentication. Health routes remain available for connectivity checks.

**Upgrade the workstation, both node services and the sandbox image together.**
The [protocol-v3 deployment record](docs/DEPLOYMENT_V3.md) documents the completed
upgrade, live node acceptance and rollback location. The subsequent
[ingress guard update](docs/INGRESS_GUARD.md) addresses the reported classifier false positives.
Protocol v3 binds protected traces to the language, runtime and target filename
as well as the source/harness hashes. Ingress results bind the language and
original/sanitized hashes plus the pinned model and classification-policy identity.
A stale node blocks live verification. See the
[language verification record](docs/LANGUAGES.md) and earlier
[31 October security record](docs/SECURITY_HARDENING.md).

Choose SSH forwarding or private Tailscale endpoints to connect the workstation to the node.

### Connect through SSH

Forward the service ports from your workstation:

```bash
ssh -N -L 18000:127.0.0.1:8000 -L 18001:127.0.0.1:8001 ubuntu@YOUR_HOST
```

Set these values in the workstation's `.env`:

```dotenv
AGENTWARD_INGRESS_URL=http://127.0.0.1:18000/scan-ingress
AGENTWARD_SANDBOX_URL=http://127.0.0.1:18001/execute
```

Check `/health` on each forwarded service.

### Use Tailscale endpoints

Install [Tailscale](https://tailscale.com/download) on the workstation and the remote node, and connect both to the same tailnet. Tailscale Serve can forward the node's private Tailscale ports to the existing loopback services. On the remote node, run:

```bash
tailscale ip -4
sudo tailscale serve --bg --tcp=8000 tcp://127.0.0.1:8000
sudo tailscale serve --bg --tcp=8001 tcp://127.0.0.1:8001
tailscale serve status
```

Replace `<NODE_TAILSCALE_IP>` below with the address printed by `tailscale ip -4`. You can also use the node's MagicDNS name when MagicDNS is enabled. Set the workstation's `.env` to:

```dotenv
AGENTWARD_INGRESS_URL=http://<NODE_TAILSCALE_IP>:8000/scan-ingress
AGENTWARD_SANDBOX_URL=http://<NODE_TAILSCALE_IP>:8001/execute
```

Verify connectivity from the workstation:

```bash
curl --fail "http://<NODE_TAILSCALE_IP>:8000/health"
curl --fail "http://<NODE_TAILSCALE_IP>:8001/health"
```

The HTTP traffic travels inside Tailscale's encrypted network, and Serve exposes these ports only within the tailnet. Restrict access to authorized operators using tailnet grants or ACLs. This setup uses the Tailscale address directly and needs no SSH port forward. Restart the dashboard after changing these endpoint URLs so it loads the new configuration.

Docker containers disable networking and use a read-only root filesystem and
inputs, 256 MiB memory/swap ceilings, CPU/PID limits, and bounded writable tmpfs.
A trusted root tracer writes evidence into a separate ACL-protected directory;
the immutable bootstrap drops to UID/GID 65534 with no effective/permitted
capabilities before loading source. Payloads cannot alter evidence or write
host-backed files. Output, trace, event-count and execution-time limits fail
closed, and containers are reaped on failure. Docker failure never triggers host
execution on the remote server. The client requires protected protocol-v3 traces
and source/harness SHA-256 matches. Node requests disable redirects and ambient
HTTP proxies so bearer credentials cannot be forwarded unexpectedly.

Bodies are limited to 2 MB at the nodes and 32 KiB at the dashboard before JSON
parsing. Source/harness fields are capped at 200,000 characters. The nodes reject
new work when their two classifier or three sandbox slots are occupied, with
HTTP 429 and `Retry-After`. WebSocket telemetry has a 32-connection cap and bounded
replay writes. Additional transport-level protection belongs at the network edge.

## Steering and security boundaries

`POST /api/steer` accepts additive restrictions such as:

```json
{"constraint":"Forbid subprocess calls; enforce pathlib commonpath"}
```

The active dashboard session shares a monotonically increasing policy revision across batch workers. Runtime checks and patch reviewers receive the current constraints. A changed revision invalidates an in-flight approval; stale approvals cannot commit a remediation. Recognized subprocess/path restrictions also have AST enforcement. Broader natural-language constraints are assessed by the ensemble and are not claimed to be a complete formal policy language.

The monitor inspects each tool trajectory for drift, attempts to bypass review, covert environment inspection and forbidden actions. A detected violation halts the session and rewinds affected workspaces. Restarting the dashboard starts a new session; no UI control can waive a mandatory gate.

Static cross-file analysis resolves imports, function/method calls, keyword arguments and return propagation to a bounded fixed point. Decorators, upstream sanitization assumptions, environment integrity and SQLite thread-sharing assumptions become explicit remediation assertions. Reflection, dynamic dispatch and external libraries remain coverage limits.

Self-play uses a bounded scenario language, not model-generated executable harnesses. Storage/replay, URL decode/replay, cleanup-entry and deterministic symlink interleaving scenarios run only inside the sandbox. A storage adapter demonstrates replay robustness, not necessarily a native persistence vulnerability. Unsupported scenarios and failed positive controls are not counted as neutralized.

## API

| Method | Route | Result |
| --- | --- | --- |
| GET | `/api/health` | Running state and phase identifiers |
| GET | `/api/languages` | Supported extensions, runtimes and adapter scope |
| GET | `/api/providers` | Pre-flight status and selected topology; `?force_refresh=true` retests |
| POST | `/api/providers/mode` | `{"mode":"all_three"}` changes subsequent ensemble selection |
| POST | `/api/steer` | Add a session restriction |
| POST | `/api/run` | `{"target_file":"poisoned_app.py"}` or a supported JavaScript/TypeScript workspace path |
| POST | `/api/batch` | Run the benchmark corpus with concurrency capped at three |
| POST | `/api/clean` | Prune temporary workspaces when idle |
| GET | `/api/metrics` | Token, cost, outcome and timing metrics |
| GET | `/api/executive-brief` | Escaped HTML, Markdown, evidence, assumptions and graph |
| GET | `/api/sarif` | Download SARIF v2.1.0 |
| WebSocket | `/ws/telemetry` | Replayable, run-tagged events |

## Evidence and verification

The [31 October live multilingual acceptance](docs/LIVE_MULTILANGUAGE.md) records
fresh Meta-generated JavaScript/TypeScript repairs, the benign Node control,
94 passing local tests and the remaining browser findings.

See the [current hardening verification](docs/SECURITY_HARDENING.md) and the
[historical 30 October record](docs/VERIFICATION.md). Earlier remote acceptance
does not certify a newly deployed node or the current protocol.

Reports are written atomically under `reports/`, with separate per-run archives:

- `benchmark_metrics.json`: per-file outcomes, votes, pre-flight state, usage and latency.
- `agentward_sarif_report.sarif`: findings and verified fixes in SARIF v2.1.0.
- `executive_brief.md` / `.html`: evidence-derived executive assessment and unresolved assertions.
- `live_e2e_verification.json` / `live_e2e_telemetry.json`: live acceptance results when the E2E driver runs.

Model executive commentary is labeled advisory and cannot change verified outcomes. Dry-run results use `SIMULATED_REMEDIATION` / `SIMULATED_FALSE_POSITIVE`, never production `REMEDIATED` / `FALSE_POSITIVE`, and export no verified SARIF fixes.

```bash
. venv/bin/activate
python -m unittest discover -v
ruff check --select E9,F63,F7,F82,F401 . --exclude venv,worktrees,patches,reports
python -m tests.run_e2e --live --base http://127.0.0.1:8080
```

Run the real Docker security checks separately (also enforced in CI):

```bash
docker build -t agentward-sandbox:multilang-v3 -f security/Dockerfile.sandbox .
AGENTWARD_TEST_DOCKER=1 SANDBOX_IMAGE=agentward-sandbox:multilang-v3 \
  python -m unittest tests.test_docker_security tests.test_multilanguage_docker -v
python3 tools/manage_cybersecurity_skills.py verify
```

The test suite covers all ensemble modes, quota cascade, invalid credentials, Responses/Chat Completions payloads, reasoning/cache stability, usage costs, steering, misalignment denial and rewind, cross-module taint, CodeShield failures, multi-step controls and simulation/production evidence separation.

For an explicit offline demonstration using deterministic model fixtures and known test targets:

```bash
AGENTWARD_FORCE_LOCAL=1 python -m tests.dry_run_dashboard
python -m tests.run_e2e --base http://127.0.0.1:18081
```

Host execution is test-only and never yields verified production evidence. Never direct that demonstration at untrusted external source.
