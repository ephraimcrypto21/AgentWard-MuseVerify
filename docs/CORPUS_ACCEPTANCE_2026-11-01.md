# ECMAScript and TypeScript corpus acceptance — 1 November 2026

All eight requested acceptance cases passed live: the four named vulnerable
targets were remediated and the four benign controls were dropped without patch
synthesis. The complete 13-file corpus produced **eight `REMEDIATED`, four
`FALSE_POSITIVE`, and one `INCONCLUSIVE`** result. The inconclusive case retains
its static CWE-338 finding; it is not counted as a verified repair or benign code.

This record covers the corpus introduced at `fad97dbef2e7e96f44c6e85fb61d6984b31bb947`
with the diagnostic-baseline, coverage-accounting and ingress-retry fixes
described below. It supersedes earlier acceptance counts for this corpus.

## Contract, classifier and test evidence

- All **13 targets** across `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` and `.cts` parse
  through `language_adapters.py` and have complete `ecmascript_harness.py` probe
  coverage. None returns `UNSUPPORTED_LANGUAGE`, `INVALID_SOURCE` or
  `UNSUPPORTED_TARGET`.
- All **six TypeScript files** pass Tree-sitter type erasure, JavaScript reparsing
  and real Purple Llama CodeShield scanning without engine or syntax errors.
  The original-source scans return clean even for the vulnerable targets;
  exploit probes and static taint findings supply the vulnerability evidence.
- All **17 exported functions** return successfully for `agentward_normal` in
  the remote Docker sandbox. Dedicated baseline probes verify UID/GID 65534;
  complete, protected protocol-v3 traces bind the source and harness hashes,
  filename, language and Node runtime.
- All **13 current sources** receive unchanged-source `ALLOW` from the real
  `Horizon-Labs/prompt-injection-guard-small` model under classifier contract v2.
  The largest measured injection score is **0.017127**, below the unchanged
  **0.40** threshold. No source was sanitized or exempted by filename.
- **99 tests passed in 77.740 seconds, with no skips**, using
  `AGENTWARD_TEST_DOCKER=1` and `agentward-sandbox:multilang-v3`. The suite includes
  the new corpus and ingress-retry regressions. Ruff correctness checks and
  `python -m pip check` also passed.

The workstation uses Python 3.14.8. Docker tests use the multilang-v3 image with
Node 24. Live tests call the authenticated remote classifier and Docker node,
with real `muse-spark-1.3` synthesis and independent `muse-wonder-1.0` review.
Unit-test model fixtures remain separate from these live records.

## Final live outcomes

Every filename below is under `benchmark_targets/`. Run IDs identify the
accepted local evidence and patch directories.

| Target | Final result | Run ID |
| --- | --- | --- |
| `cwe_78_cmd.js` | `REMEDIATED` | `CORPUS-01-e67d17f53db3` |
| `cwe_78_cmd_mjs.mjs` | `REMEDIATED` | `CORPUS-RETRY-1-abde529eee83` |
| `cwe_89_sqli.ts` | `REMEDIATED` | `CORPUS-03-db93fd42ba56` |
| `cwe_89_sqli_cjs.cts` | `REMEDIATED` | `CORPUS-04-a9cf87a8833c` |
| `fp_node.mjs` | `FALSE_POSITIVE` | `CORPUS-05-498616710061` |
| `fp_node_cjs.cjs` | `FALSE_POSITIVE` | `CORPUS-06-92dda935f6b9` |
| `fp_typescript_safe.ts` | `FALSE_POSITIVE` | `CORPUS-RETRY-2-0e04d345028f` |
| `fp_typescript_safe.mts` | `FALSE_POSITIVE` | `CORPUS-08-6f7e3d0fa6e4` |
| `cwe_78_cmd_alias.js` | `REMEDIATED` | `CORPUS-10-0da0811331df` |
| `cwe_78_cmd_ping.cts` | `REMEDIATED` | `CORPUS-11-60b37e376e2d` |
| `cwe_89_sqli_like.cjs` | `REMEDIATED` | `CORPUS-12-71dfa6fde5ed` |
| `cwe_89_sqli_login.mts` | `REMEDIATED` | `CORPUS-13-1dcee2d2c611` |
| `cwe_338_weak_token.cjs` | `INCONCLUSIVE` | `CORPUS-09-ec901cc3a28f` |

Each repair reproduced the original exploit, passed runtime policy, independent
review, CodeShield and AST tripwire checks, and neutralized all three self-play
scenarios: syntax mutation, stored-value replay and URL-encoding replay.
That is **24 neutralized scenarios, zero survivors and zero inconclusive
scenarios**. Phase 5 preserved the recorded normal result, blocked the exploit
and triggered the tripwire only for its decoy input. TypeScript execution used
the original TypeScript source in Node 24 inside Docker.

The four benign controls have no target static findings and return `BENIGN`
from Phase 2's SQL/command probes. Mandatory Phase 3 policy review still runs;
Phases 4, 4.5, 5 and 5.1 are skipped. Provider telemetry confirms **zero
`patch_synthesis` and zero `patch_verification` calls** for each control.
Policy review and advisory executive commentary still use model calls.

## Defects found and corrected

1. `cwe_78_cmd_ping.cts` initially failed normal execution because `ping` was
   absent and the sandbox has no network. The fixture now echoes the supplied
   host through a shell `printf` command, preserving `pingHost(host: string):
   string` and its intentional shell interpolation. Normal execution and
   command-exploit positive controls both pass. Repair candidates stay separate
   from the vulnerable benchmark source.
2. SQL probes previously risked dismissing `cwe_338_weak_token.cjs` as a false
   positive. The harness now declares its covered CWEs. When no runtime exploit
   is observed, static findings outside those CWEs remain in
   `unverified_findings`, with an `INCONCLUSIVE` outcome. This target's bound
   SQL query is safe under the probes, but the `Math.random()` token weakness
   has no matching runtime verifier. Its output exposes only `hasToken`, so
   these tests cannot establish token unpredictability.
3. Concurrent live startup initially denied two targets because classifier
   capacity was exhausted. Separate authenticated requests reproduced HTTP 429
   with `Retry-After: 1`. The client now makes at most three identical requests
   for short 429 delays, preserving every classifier evidence check. The two
   affected targets passed sequential live reruns, and a subsequent three-call
   concurrent ingress check returned verified `ALLOW` for all three calls.
   The initial failures remain archived and are referenced by `previous_attempts`
   in the final records; they are not represented as successful first attempts.

These fixes require the updated workstation client and dashboard. The existing
remote services and `agentward-sandbox:multilang-v3` already supply the required
protocol-v3 evidence; the model policy and sandbox protocol did not change.

## Artifact verification

The combined outputs contain the latest result for each of the 13 targets:

- `reports/benchmark_metrics.json`: 13 completed/triaged files, eight repairs,
  four false positives, 24 neutralized self-play scenarios and zero survivors.
- `reports/executive_brief.md` and `.html`: all 13 outcomes, verified CWEs,
  tripwires, provider telemetry, coverage limits and labeled advisory commentary.
- `reports/agentward_sarif_report.sarif`: valid SARIF 2.1.0 against the checked-in
  schema, with **eight verified fixes and one unresolved CWE-338 warning**.
  `executionSuccessful` remains false because that finding is inconclusive.
- `patches/<run-id>/<stem>_patched.<extension>` and adjacent `.diff` files:
  eight accepted repairs with preserved extensions, exports and signatures.

Artifact checks reparsed and rescanned every saved patch, reconstructed the
baseline/regression harness hashes, matched patch hashes to the protected
regression evidence, and applied each diff in a temporary directory to confirm
it reconstructs the saved patch exactly. SARIF inserted content matches those
same files. No benign or inconclusive record has a patch or verified SARIF fix.
Semantic hunting of intentionally vulnerable siblings remains separate from
accepted repairs.

The local dashboard was restarted after confirming it was idle and had no
operator constraints to restore. It remains on `127.0.0.1:8080` with
`--ws-max-size 1024 --ws-max-queue 4`. Its metrics and SARIF endpoints match the
saved canonical files; its executive brief contains the same evidence, sorted
by target after reload. Health and API checks are saved in
`dashboard-restart.json` and `dashboard-validation.json` under the evidence
directory below.

Detailed local evidence is under `reports/corpus-2026-11-01/`, including
`static-contracts.json`, `baseline-summary.json`, per-file baseline/phase events,
`live-initial-results.json`, `live-results.json`, `final-unit-tests.log`,
`ingress-concurrency.json`, `ingress-concurrency-after.json`, and
`artifact-verification.json`. Initial static/baseline failures are preserved
separately. Reports and patches are local runtime artifacts and are excluded
from Git; this document records their acceptance without committing source
payloads, credentials or model transcripts.

## Reproduce

With the configured virtual environment, live Meta credentials and authenticated
node endpoints already active:

```bash
. venv/bin/activate
AGENTWARD_TEST_DOCKER=1 SANDBOX_IMAGE=agentward-sandbox:multilang-v3 \
  python -m unittest discover -v
ruff check --select E9,F63,F7,F82,F401 . --exclude venv,worktrees,patches,reports
python -m pip check
```

For a new complete live corpus report, use one shared `RunReport` so subsequent
targets accumulate in the canonical report instead of replacing it:

```python
import asyncio
from pathlib import Path
from main_pipeline import run_unified_pipeline
from reporting import RunReport

async def verify_corpus():
    report = RunReport(mode='live')
    extensions = {'.js', '.mjs', '.cjs', '.ts', '.mts', '.cts'}
    for target in sorted(Path('benchmark_targets').iterdir()):
        if target.suffix in extensions:
            record = await run_unified_pipeline(str(target), report=report)
            print(target, record['outcome'])
    report.export()

asyncio.run(verify_corpus())
```

These results cover the recorded sources, scalar inputs and finite exploit
probes. They do not establish complete vulnerability detection, all business
behavior, whole-project TypeScript compilation or cryptographic token strength.
