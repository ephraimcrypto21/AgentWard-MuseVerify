# Live multilingual acceptance — 31 October 2026

The local workstation completed live verification of the three Node targets using
its configured Meta credentials and the authenticated remote ingress/Docker node.
These runs used real model responses, the pinned ingress classifier and protected
protocol-v3 execution evidence. No model fixtures or host-execution fallback were
used. The benchmark source files remain unchanged.

| Target | Live result | Run ID |
| --- | --- | --- |
| `benchmark_targets/cwe_78_cmd.js` | **REMEDIATED** | `PC-LIVE-001-fa4563c3945a` |
| `benchmark_targets/cwe_89_sqli.ts` | **REMEDIATED** | `PC-LIVE-002-211e0d195a98` |
| `benchmark_targets/fp_node.mjs` | **FALSE_POSITIVE** | `PC-LIVE-003-828b79f1a62d` |

Both repairs passed on their first candidate after the review-contract fix. Spark
synthesized the candidates and Wonder independently reviewed them. Each passed
CodeShield, three viable adversarial replay scenarios with zero survivors,
normal-behavior regression and the decoy tripwire checks. Semantic hunting ran
on two siblings per repair and reported no variants in that scope. The benign
control required no repair and correctly produced no verified fix.

## A live-review failure found and corrected

The initial runs could reproduce the vulnerabilities but failed during Phase 4.
Reviewers demanded final remediation evidence from phases that cannot run until
a candidate exists, treated unrelated sibling benchmark findings as target
blockers, and in one Python attempt treated the required tripwire as an injected
instruction. Subsequent synthesis responses sometimes became refusal prose and
failed source parsing.

The application now explicitly scopes synthesis and review to a Phase 4 candidate.
It supplies the observed ingress, original sandbox and runtime-policy evidence,
including source and execution-artifact hashes, while retaining the verification
mode. Model votes carry `approval_scope: phase4_candidate`. Later gates remain
pending until the orchestrator runs them. Unresolved risks affecting the target,
new cross-file hazards, malformed votes, scanner failures and stale policy still
block acceptance. The model cannot waive any gate or grant final remediation.

## Artifacts and verification

Local accepted candidates:

- `patches/PC-LIVE-001-fa4563c3945a/cwe_78_cmd_patched.js`
- `patches/PC-LIVE-002-211e0d195a98/cwe_89_sqli_patched.ts`

The shared live report at `reports/agentward_sarif_report.sarif` contains **two
verified fixes**, and passed the repository's SARIF 2.1.0 schema. Both saved
candidate SHA-256 hashes match the final protected sandbox evidence. Dashboard
SARIF and executive-brief endpoints returned the same three outcomes and two
verified remediations. The full records, telemetry and artifact checks are retained
locally in `reports/pc-acceptance/`; runtime outputs and credentials stay out of Git.

The three targets ran sequentially through `run_unified_pipeline`, the same
orchestrator used by the CLI, with one shared live `RunReport` so the final SARIF
retains both fixes. Separate CLI invocations also work, but each creates its own
report and replaces the latest canonical export; per-run archives remain available.

The original Python case was also rechecked after the shared review fix.
`poisoned_app.py` completed live **REMEDIATED** in run
`PC-LIVE-PY-3321b3c2744d`, with its accepted candidate at
`patches/PC-LIVE-PY-3321b3c2744d/poisoned_app_patched.py`. It passed the required
tripwire, three adversarial scenarios and runtime regression. Semantic hunting
reviewed 51 siblings and reported the intentionally vulnerable Python SQL
benchmark as one suspicious variant; this static lead was not treated as a
runtime-verified repair. Its separate report is retained under
`reports/pc-acceptance/python-live/`, preserving the requested three-target Node
report at the canonical SARIF path.

## Workstation checks

- **94 automated tests passed with no skips**, including the real local Docker
  security and multilingual suites. New tests verify that candidate approval
  cannot override CodeShield and that observed fixture evidence is not promoted
  to live evidence when passed to review.
- Ruff correctness checks, `pip check`, and the 818-skill integrity check passed.
- Workstation: Python 3.14.8 and Docker 28.5.2. The sandbox image provides
  Python 3.12.16 and Node 24.22.2.
- Both configured remote services returned healthy responses and rejected
  unauthenticated execution/classification requests with HTTP 401.
- Live dashboard checks rejected unsupported extensions, paths outside the
  workspace, missing target fields, foreign browser origins and foreign hosts.
- The restarted dashboard uses loopback port 8080 with WebSocket message size
  1024 and queue length 4.

Meta's Spark/Wonder pair was healthy. The optional Anti-Gravity provider had no
healthy model, and the configured Custom provider returned HTTP 401. Both were
excluded by pre-flight; this record does not claim acceptance of those providers.

## Browser findings still open

Chromium 156 checked the dashboard at 1440, 768 and 375 pixels. Navigation between
brief/map tabs, both diff layouts, source-path input and basic keyboard focus
worked. There were no page errors, failed network responses or console errors on
an uninstrumented load. The instrumented performance pass emitted an expected
warning when the protected brief iframe rejected an injected observer script.

Desktop and tablet had no horizontal page overflow. At 375 pixels, the document
expanded to 755 pixels because header badges, selectors and controls did not fit.
Automated accessibility checks reported invalid tablist children, low-contrast
status text, invalid list content, and a non-focusable scroll region at narrower
sizes. These frontend findings remain open; no frontend changes were made in
this acceptance fix. Screenshots and axe details are retained in the local report.
There is no committed screenshot baseline, so visual regression comparison is
inconclusive. Automated checks alone do not establish accessibility conformance.

These results cover the tested inputs and runtime behavior. Static-analysis limits,
probabilistic model behavior and the trusted host/service assumptions still apply.
