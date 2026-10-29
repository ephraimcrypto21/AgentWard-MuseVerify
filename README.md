# 🛡️ AgentWard + MuseVerify

### Zero-Trust Agentic Remediation Harness & Runtime Circuit Breaker

> **Never trust an AI patch you haven't watched execute.**

Most agentic remediation tools ask a model to fix a bug, then trust the model's word that it worked. This harness treats every AI-proposed fix as guilty until it is behaviourally proven innocent: a prompt-injection shield guards the ingress, an isolated syscall-instrumented sandbox decides what is actually exploitable, and a patch is only accepted after it survives an adversarial self-play loop it has never seen before.

---

## 🔥 The Problem

AI coding agents are being handed commit access to production codebases, and three failure modes are already well documented:

- **Hallucinated fixes.** The model produces a confident-looking diff that compiles, passes review, and closes nothing. Exit code `0` is not evidence that an exploit is dead.
- **Secondary vulnerabilities.** Hardening one sink routinely opens another — a "safe" refactor that swaps `shell=True` for an argv list while silently preserving string interpolation, or a credential move that relocates the secret without rotating it.
- **Wasted compute on false positives.** SAST engines drown teams in alerts that are never reachable at runtime. Agents burn tokens, reviewers burn hours, and the real findings drown in the noise.

Worse, the models doing the fixing are *reading attacker-controlled text*: docstrings, config blobs, and fixture data that can carry an indirect prompt injection telling the agent to exfiltrate `$META_API_KEY`.

---

## 🏰 Our Solution (Core Architecture)

A five-phase defense-in-depth pipeline. Every phase is a gate — any phase can halt the run, and only Phase 5 can declare victory.

```
 ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
 │ Phase 1  │──▶│ Phase 2  │──▶│ Phase 3  │──▶│ Phase 4  │──▶│ Phase 5  │
 │ Ingress  │   │ Sandbox  │   │ Runtime  │   │ CodeShield│  │Regression│
 │  Shield  │   │  Triage  │   │  Hooks   │   │   Gate   │   │   Test   │
 └──────────┘   └──────────┘   └──────────┘   └────┬─────┘   └──────────┘
                                                    │
                                            ┌───────▼────────┐
                                            │  Phase 4.5     │
                                            │  Self-Play     │
                                            └────────────────┘
                                                    │
                                            ┌───────▼────────┐
                                            │  Phase 5.1     │
                                            │ Semantic Hunt  │
                                            └────────────────┘
```

### Phase 1 — Ingress Shield

Every candidate file is scanned by **Meta Prompt-Guard-86M** *before* any of its text reaches the reasoning model. Payloads hidden in docstrings, comments, or string literals are flagged and sanitized, so an injection cannot rewrite the agent's own instructions mid-run. Legitimate content passes through byte-identical.

### Phase 2 — Docker Sandbox (Zero-Network Isolation)

The candidate is copied into a throwaway worktree and executed inside a locked-down container:

```python
"--network", "none",        # no egress, no C2 callbacks
"--memory", "256m",         # memory ceiling
"--cpus", "0.5",            # CPU ceiling
"--cap-add", "SYS_PTRACE",  # only what tracing needs
```

A generated harness drives the suspect sink with a real payload. Verdicts are **behavioural, not exit-code based**: the container is traced with `strace -f` and an in-process `sys.addaudithook` shim (identical normalized schema, automatic fallback when `strace` is absent). The auditor reasons over the actual `execve` / `openat` / `connect` chain, so a payload that "passed" because the interpreter exited `0` is caught, and a sink that was never reachable is dropped as a **false positive** instead of being patched for nothing.

### Phase 3 — Runtime Hooks & Checkpointing

Before the agent is allowed to act, the worktree is snapshotted: every file is SHA-256 hashed into a manifest. Each proposed tool call is then checked against policy (`enforce_permissions.py`) and recorded with a hash of the action. Any unauthorized or out-of-scope mutation trips the circuit breaker, and `rewind()` restores the worktree from the manifest — the agent's blast radius is bounded to a directory it cannot leave.

### Phase 4 — CodeShield Gate

Patch synthesis runs on Meta models, then the result faces **three independent checks before anything is written**:

1. **Cross-model secondary audit** — a *different* provider (Anti-Gravity / Gemini) reviews the diff and votes `APPROVE` / `REJECT` with reasoning. Divergence halts.
2. **Purple Llama CodeShield** — Purple Llama security scanning with `Language.PYTHON`. Scanner errors fail the gate.
3. **AST contract and architecture validation** — the module must parse, preserve public signatures, and avoid introduced cross-file taint, races, async blocking, and file/database TOCTOU hazards.
4. **Deception validation** — a fake decoy, logging helper, and public input guard must be structurally connected; Phase 5 must observe the tripwire firing while normal input stays quiet.

Public function signatures must survive unchanged, so downstream callers don't break.

### Phase 5 — Regression Test

The *same* exploit from Phase 2 is replayed against the patched container. If the sink still escapes, the patch is rejected and the run fails loudly. Only a clean re-test releases the patch.

---

## 🧪 Advanced Features

### 🎭 Self-Play Adversarial Mutation (Phase 4.5)

A patch that only neutralizes the one payload we happened to try is a coincidence, not a fix. Between the CodeShield gate and regression, the model is prompted to generate **mutated, obfuscated variants of the original exploit** — different comment placement, keyword casing, whitespace, encoding, and chained payloads:

```
'/**/UNION/**/SELECT/**/1,'AGENTWARD_SQLI'/**/--
' union all select 1,'AGENTWARD_SQLI' #
'%0aUNION%0aSELECT%0a1,'AGENTWARD_SQLI'%0a--
```

Every variant is replayed against the patched sandbox. **A positive control first replays every mutation against the original file.** Only effective original exploits blocked by a valid patched run count as neutralized. Invalid variants and incomplete executions are reported separately. At least one viable mutation must be exercised; a surviving exploit or incomplete execution rejects the patch. The gate fights the model with the model.

### 🍯 Automated Tripwire Synthesis (Deception)

The patch prompt does more than fix — it instructs the model to plant a structural honeypot beside the fix: a decoy credential (`META_API_KEY_LEGACY = "sk-legacy-..."`) wired to an alerting logger through a `_tripwire()` helper that emits `TRIPWIRE` at `WARNING`. The guard is a single cheap equality check at the top of the sink: inert for normal input, identical return value, no extra I/O — but any attacker (or credential scanner) still poking the *old* surface announces itself. You get detection after remediation, not just a closed bug.

### 🔎 Semantic Variant Hunting (Phase 5.1)

The same missing control usually exists more than once. After a clean remediation, `semantic_hunter.py` extracts the **semantic root cause** of the bug and sweeps the surrounding codebase for structurally different but semantically identical flaws — bypassing rigid AST matching entirely. Benign lookalikes (parameterized queries, argv-list `subprocess`, `secrets` module) are explicitly excluded from the report.

---

## 📋 System Requirements & Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.10+** | 3.12 is what the sandbox image ships |
| **Docker Engine** | Rootless is fine; socket access required |
| **`strace`** | Baked into the sandbox image by the deploy script |
| **Uvicorn + FastAPI** | Both daemons and the dashboard |
| **Model credentials** | `META_API_KEY` for synthesis/audit; a second provider for cross-model consensus |
| **Optional** | `torch` + `transformers` on the node for the local Prompt-Guard |

> 🌐 **Runs anywhere.** The reference deployment puts the daemons on an AWS Lightsail node reached over a Tailscale mesh, so the sandbox never shares a kernel with the developer laptop. Nothing in the architecture is Lightsail-specific — **the remote daemon runs unchanged on any standard Linux VM, bare-metal host, or Kubernetes cluster.** `AGENTWARD_FORCE_LOCAL=1` runs the same sandbox loop on the host for single-machine demos.

---

## 🚀 Installation & Deployment

### 1. Clone and prepare the client

```bash
git clone https://github.com/ephraimcrypto21/AgentWard-MuseVerify.git
cd AgentWard-MuseVerify
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn pydantic python-dotenv httpx codeshield
```

### 2. Configure credentials

Create `.env` (never commit it — it is already gitignored):

```bash
ACTIVE_AI_PROVIDER=meta
META_API_KEY=sk-...
META_API_BASE_URL=https://api.meta.ai/v1

# Secondary voter for cross-model consensus
AGY_SELECTED_MODEL=gemini-4-argon

# Optional bring-your-own-key endpoint
CUSTOM_API_URL=
CUSTOM_API_KEY=
CUSTOM_MODEL_NAME=openai/gpt-6.1-sol
```

### 3. Deploy the node daemons

On the Linux host that will run the sandbox, as a user with Docker access:

```bash
git clone https://github.com/ephraimcrypto21/AgentWard-MuseVerify.git ~/agentward-node
cd ~/agentward-node
python3 -m venv venv
./venv/bin/pip install fastapi uvicorn pydantic python-dotenv httpx transformers torch
```

Run the deployment script — it syncs the code, builds the `strace`-enabled sandbox image, installs both systemd units, and asserts that telemetry is live:

```bash
sudo bash deploy_remote_services.sh
```

```bash
# ingress_server.py  → 0.0.0.0:8000  (Stage 1 Prompt-Guard)
# sandbox_server.py  → 0.0.0.0:8001  (Stage 2 syscall sandbox)
```

> The deploy script preserves local changes and only refreshes clean checkouts through a fast-forward merge. It never resets the checkout.

Confirm the node is streaming telemetry:

```bash
curl -s http://<node>:8001/health
# {"status":"ok","service":"MuseVerify Sandbox Node","docker":true,
#  "sandbox_image":"agentward-sandbox:latest","trace_capable":true,
#  "syscall_telemetry":"strace+audit-hook (auto fallback)"}
```

If the daemons move, override the endpoints with environment variables instead of editing source:

```bash
export AGENTWARD_INGRESS_URL="http://<node>:8000/scan-ingress"
export AGENTWARD_SANDBOX_URL="http://<node>:8001/execute"
```

They default to the constants at the top of `museverify_stage2.py`, which you can still edit if you prefer.

The client detects a node running a pre-telemetry build and transparently degrades to a local audit-hook run rather than silently trusting exit codes. When `trace_capable` is `false`, the image lacks `strace`, so only the in-process audit hook records events — rebuild `agentward-sandbox:latest` to restore kernel-level tracing.

### 4. Launch the local dashboard

```bash
source venv/bin/activate
python dashboard.py                      # 127.0.0.1:8080
DASHBOARD_PORT=9000 python dashboard.py  # or pick your own
```

Open <http://127.0.0.1:8080>. Telemetry binds to `ws(s)://<host>/ws/telemetry` on the same origin, so a reverse proxy or SSH tunnel (`ssh -L 8080:127.0.0.1:8080 <node>`) works without code changes. `DASHBOARD_HOST` defaults to `127.0.0.1` — set it to `0.0.0.0` to expose the cockpit on your LAN.

---

## ⚡ Quick Start / Usage

**From the dashboard**

1. Pick a target from **Select Target** — `poisoned_app.py` is the fully loaded demo (SQL injection *plus* an indirect injection targeting `$META_API_KEY`). The dropdown also offers the three CWE fixtures, both injection fixtures, and two benign decoys so you can watch a false positive get dropped unprompted.
2. Press **▶ Run Autonomous Triage**.
3. Watch the seven phase cards resolve in real time. The telemetry row streams the syscall trail, the auditor's reasoning, the self-play variants, the armed tripwire, and any semantic matches.

**From the CLI**

```bash
# Single target
venv/bin/python main_pipeline.py poisoned_app.py

# Whole corpus, concurrent
venv/bin/python main_pipeline.py benchmark_targets
```

The corpus ships 25 files: 3 real CWEs (`cwe_89_sqli.py`, `cwe_78_cmd.py`, `cwe_338_crypto.py`), 2 indirect prompt injections (`poison_docstring.py`, `poison_variable.py`), and 20 benign false-positive decoys (`fp_01.py`–`fp_20.py`).

**Reading the telemetry**

| Signal | Meaning |
|---|---|
| `EXPLOITABLE` + `confirmed` | A payload physically reached the sink. Decisive. |
| `SUSPICIOUS` | Weak evidence only (unknown `execve`, outside writes, blocked egress). |
| `BENIGN` | Harness ran, nothing escaped. |
| `PATCH ROBUST` | Every self-play mutation was neutralized. |
| `PATCH BYPASSED` | A mutation survived — patch rejected. |
| `TRIPWIRE / ARMED` | Honeypot planted in the patched file. |
| `N VARIANT(S)` | Semantically identical bugs still present elsewhere. |

A full run tightens the loop: exploit confirmed → patch gated → mutation-proofed → regression clean → variants hunted.

---

## Routing, telemetry, and compliance artifacts

The default centerpiece stays on Meta: `muse-spark-1.3` synthesizes patches and
checks runtime policy; `muse-wonder-1.0` extracts root causes and hunts variants.
`gemini-4-argon` reviews patches independently through the sandboxed Anti-Gravity
CLI. Missing, malformed, or negative policy/review votes block the run.

Custom/BYOK routing accepts `openai/gpt-6.1-sol` for gateways and `gpt-6.1-sol`
for direct OpenAI endpoints. Set `CUSTOM_API_URL` to a full Chat Completions or
Responses endpoint, `CUSTOM_API_KEY`, and `CUSTOM_MODEL_NAME`. Optional selectors
are `POLICY_PROVIDER`, `PATCH_PROVIDER`, `PATCH_MODEL`, `AUDITOR_PROVIDER`,
`SECONDARY_PROVIDER`, and `SECONDARY_MODEL`. Keep synthesis and independent review
on different providers. `query_ai` preserves its string return and existing
positional arguments while adding keyword-only `task` and `reasoning_effort`.

Sol supports `low`, `medium`, `high`, `xhigh`, and `max`: policy uses `medium`;
patch synthesis/review and semantic hunting use `xhigh`. The router sends
`reasoning_effort` to Chat Completions and `reasoning.effort` to Responses.
Native prompt-prefix caching uses stable system prefixes and `prompt_cache_key`
for Sol; security decisions are never cached locally. Set `CUSTOM_PROMPT_CACHE=0`
for a gateway that does not support cache hints. Provider-reported cached tokens
are included in telemetry. See the [official reasoning documentation](https://developers.openai.com/api/docs/guides/reasoning)
and [prompt caching documentation](https://developers.openai.com/api/docs/guides/prompt-caching).

Every single-file and batch invocation writes:

- `reports/agentward_sarif_report.sarif` — schema-valid SARIF 2.1.0, findings,
  verified replacements, terminal outcomes, and benchmark/provider telemetry.
- `reports/benchmark_metrics.json` — triaged files, dropped alert percentage,
  sanitized instruction blocks, behavioral anomaly categories, viable mutations
  neutralized/survived, invalid/inconclusive variants, and MTTR.
- `reports/runs/<id>/` — snapshots preserved per invocation.
- `patches/<run-id>/*_patched.py` and `.diff` — immutable verified patch and a
  deterministic unified diff against the original source. Candidates live under
  `patches/.candidates/` until regression and tripwire checks succeed.

MTTR measures start through successful Phase 5, excluding later variant hunting.
The live dashboard value includes active elapsed time and is provisional. The
false-positive reduction percentage is dropped alerts divided by triaged alerts;
inconclusive runs are never dropped. Anomaly counts represent flagged behavioral
signal categories, with actual Docker/strace/audit-hook backend recorded. No
metric claims eBPF observation when that backend was not used.

Tokens and latency come from each provider response/request. Missing usage or
pricing stays unknown. Sol's estimated standard USD tariffs come from the
[model documentation](https://developers.openai.com/api/docs/models/gpt-6.1-sol).
Configure other providers or gateway tariffs through `AI_PRICING_JSON`, keyed by
`provider:model` (or model), with per-million-token fields `input`, `output`,
`cached_input`, and optionally `cache_write`. These are estimates, not invoices.

The dashboard streams aggregate KPIs and per-file events through
`/ws/telemetry`, including reconnect replay. Select a batch run to inspect its
seven cards, syscall trail, self-play and unified/side-by-side diff. Download the
latest report through **📥 Export SARIF v2.1.0 Report** or `GET /api/sarif`.
Overlapping top-level jobs and workspace cleanup during a run return HTTP 409.

## Verification and deployment limits

```bash
# Automated offline verification: model fixtures, real local execution and CodeShield.
AGENTWARD_FORCE_LOCAL=1 venv/bin/python -m unittest discover -s tests -v

# Explicit offline dashboard and real HTTP/WebSocket exercise.
AGENTWARD_FORCE_LOCAL=1 venv/bin/python -m tests.dry_run_dashboard
venv/bin/python -m tests.run_e2e

# Production dashboard startup.
venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8080
```

Dry-run reports are marked `verification_mode: dry_run`. Production routes never
import model fixtures. The requested poisoned SQLi, true CWE-89 and benign FP-01
fixtures are covered, including concurrency/TOCTOU negatives, fail-closed reviews,
positive mutation controls, atomic reports, schema validation and live sockets.

Tailscale endpoints and the existing local audit-hook fallback remain available.
The local fallback is a development execution mode: removing provider secrets
from the child environment does not provide Docker's kernel or network isolation.
Set `AGENTWARD_REQUIRE_DOCKER=1` on client and node to reject local fallback in
production. Remote containers use zero network, bounded CPU/memory/processes,
minimal capabilities, no new privileges, and the service account UID for writable
workspace access. Timeout cleanup removes the container and returns an incomplete
result rather than replaying a timed-out target on the host.

Static call graphs are bounded and report coverage limits for oversized files,
dynamic dispatch/reflection and external dependencies. Concurrency findings are
conservative review signals. Passing the benchmark verifies those fixtures; it
cannot prove every possible program or scheduling interleaving safe.

---

## 🧭 Design Principles

- **Behaviour over assertions.** A patch is proven by what the kernel observed, not by a `0` exit code.
- **Two models beat one.** Synthesis and review run on different providers.
- **Everything is telemetry.** Every phase decision streams over WebSocket to the dashboard; nothing is silent.
- **Fail closed.** Only a patch that passes independent gates and regression is published as verified.
- **Assume the input is hostile.** The corpus can lie, and the agent reads it anyway.

---

<p align="center"><sub>Built for the Meta AI Hackathon. AgentWard + MuseVerify — verify, don't trust.</sub></p>
