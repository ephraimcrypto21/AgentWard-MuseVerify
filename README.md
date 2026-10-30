# AgentWard + MuseVerify

A Meta-primary security harness that inspects poisoned source, reproduces benchmark vulnerabilities in a Docker/strace sandbox, generates candidate repairs, and verifies them through independent model review, CodeShield, adversarial replay and regression tests.

**Meta remains mandatory on every live run.** `muse-spark-1.3` leads runtime policy checks and patch synthesis; `muse-wonder-1.0` leads deep semantic analysis. Verified Anti-Gravity and custom BYOK models can join as independent reviewers. Missing security evidence produces a blocked, rejected or inconclusive result.

## Seven phases

| Phase | Responsibility | Required evidence |
| --- | --- | --- |
| 1 — Ingress Shield | Classify source with Prompt-Guard-86M; remove injected instructions without breaking Python syntax | Full source coverage and a second scan of sanitized content |
| 2 — Syscall Sandbox | Execute deterministic exploit probes in an isolated workspace | Docker execution, kernel strace events and completed behavioral probes |
| 3 — Runtime Hooks | Regex/entropy screening, unanimous ensemble policy review and trajectory monitoring | Valid votes; current operator policy; denial triggers workspace rewind |
| 4 — Patch Verification | Spark synthesis, API-contract checks, cross-file analysis, independent reviewers, CodeShield and structural tripwire validation | Every applicable gate passes |
| 4.5 — Adversarial Self-Play | Replay mutated and multi-step scenarios against original and candidate code | Positive controls on original code, no surviving exploit and valid sandbox evidence |
| 5 — Regression | Replay original exploit, normal inputs and decoy guards | Exploit blocked, functional checks pass, tripwire fires only for decoy probes |
| 5.1 — Semantic Hunter | Wonder-led multi-provider analysis of imported helpers and related modules | Static paths, model findings and coverage limits reported separately from runtime proof |

Phase 2 overlaps with AST graph construction and the Stage 3 policy baseline. At most three pipeline containers execute concurrently. A successful baseline cannot substitute for later sandbox or patch evidence.

## Quick start

Python 3.12+ is recommended. The local development environment uses `venv/`.

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
# Populate Meta credentials and any optional providers in .env.
python -m uvicorn dashboard:app --host 127.0.0.1 --port 8080
```

Open [the dashboard](http://127.0.0.1:8080). The header shows the real provider pre-flight matrix. Select an ensemble, retest credentials, launch an audit, or add an operator restriction while a run is in progress.

The dashboard includes all seven phase cards, replayable WebSocket telemetry, a unified/side-by-side verified diff viewer, the executive brief, a cross-file call/taint map and SARIF export. Run controls reject cross-origin browser requests. Keep the dashboard and verification services on loopback or behind authenticated access controls.

CLI entry points use the same orchestrator:

```bash
python main_pipeline.py poisoned_app.py
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

## Remote Prompt-Guard and sandbox node

Use an Ubuntu host with Docker, a Python environment containing FastAPI/Uvicorn, PyTorch/Transformers, and a locally cached Prompt-Guard-86M model. The supplied classifier currently loads `Niansuh/Prompt-Guard-86M`; provision that artifact before starting the service. Unavailable weights fail closed.

Copy `ingress_server.py`, `ingress_sanitizer.py`, `sandbox_server.py` and the deployment script to `/home/ubuntu/agentward-node/`, then run the deployment script there with sudo. It builds a strace-capable image when needed and installs the two systemd services. Both bind to `127.0.0.1`.

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

Docker containers disable networking, limit memory/CPU/processes, drop capabilities except tracing support, and run without host credentials. Docker failure never triggers host execution on the remote server. Missing or truncated kernel-trace evidence cannot establish remediation or a benign finding. The client also checks source and harness SHA-256 hashes against the submitted artifacts.

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
| GET | `/api/providers` | Pre-flight status and selected topology; `?force_refresh=true` retests |
| POST | `/api/providers/mode` | `{"mode":"all_three"}` changes subsequent ensemble selection |
| POST | `/api/steer` | Add a session restriction |
| POST | `/api/run` | `{"target_file":"poisoned_app.py"}` |
| POST | `/api/batch` | Run the benchmark corpus with concurrency capped at three |
| POST | `/api/clean` | Prune temporary workspaces when idle |
| GET | `/api/metrics` | Token, cost, outcome and timing metrics |
| GET | `/api/executive-brief` | Escaped HTML, Markdown, evidence, assumptions and graph |
| GET | `/api/sarif` | Download SARIF v2.1.0 |
| WebSocket | `/ws/telemetry` | Replayable, run-tagged events |

## Evidence and verification

See the [verification record](docs/VERIFICATION.md) for the executed checks, deployment evidence and live provider limitations.

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

The test suite covers all ensemble modes, quota cascade, invalid credentials, Responses/Chat Completions payloads, reasoning/cache stability, usage costs, steering, misalignment denial and rewind, cross-module taint, CodeShield failures, multi-step controls and simulation/production evidence separation.

For an explicit offline demonstration using deterministic model fixtures and known test targets:

```bash
AGENTWARD_FORCE_LOCAL=1 python -m tests.dry_run_dashboard
python -m tests.run_e2e --base http://127.0.0.1:18081
```

Host execution is test-only and never yields verified production evidence. Never direct that demonstration at untrusted external source.
