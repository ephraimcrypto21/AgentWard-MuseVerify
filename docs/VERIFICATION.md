# Verification record — 30 October 2026

This record distinguishes automated checks from acceptance against the authorized Ubuntu verification node. It does not claim that static assumptions are proven or that every compatible provider was tested live.

## Local checks

- 46 automated tests passed, including all five ensemble modes, quota cascade, failed credentials, provider configuration races, concurrent auditors, Astra payloads for both API formats, reasoning escalation and cost calculations.
- Steering, stale-policy rejection, deterministic secret screening, model denial/unavailability, workspace rewind, multi-hop taint and unsupported assumptions passed.
- Real CodeShield was used in pipeline tests; a known insecure MD5 control was rejected. Engine errors cannot become clean scans.
- Compilation, Ruff correctness checks (`F,E9`), `git diff --check`, and `pip check` passed.
- Statement coverage was 82% across the imported application modules (2,235 statements). Remote sandbox execution is covered by separate live acceptance, not this coverage percentage. Python has no configured static type checker.
- The HTTP/WebSocket offline E2E passed all four expected simulated outcomes. Simulated runs never export verified SARIF fixes.
- Playwright verified seven phase cards, five ensemble choices, retesting, steering, both diff layouts and executive/taint tabs with zero page errors, including a mobile viewport. The final live server also passed browser verification with all four executive-report rows, live provider badges and replay of a real verified diff.

The final suite includes the report-rendering escaping/evidence-separation test. Model text and target names remain escaped in HTML; a simulated armed guard is never labeled runtime verified.

## Environment and remote checks

Local runtime: Python 3.14.8, FastAPI 0.135.4, Uvicorn 0.54.0, HTTPX 0.28.1, CodeShield 1.0.1, Semgrep 1.182.1, coverage 7.17.0, Ruff 0.17.3 and Playwright 1.64.1.

Remote runtime: Ubuntu, Python 3.12.3, Docker 29.1.3 and `agentward-sandbox:latest` with strace. Both systemd services are active and bind to loopback; the workstation uses SSH forwards. Deployed `ingress_server.py`, `ingress_sanitizer.py` and `sandbox_server.py` match local SHA-256 hashes.

Prompt-Guard-86M loaded successfully. A multi-window input exceeding 512 tokens was classified, sanitized and rescanned with complete coverage. Docker smoke execution returned exit 0, kernel strace events and matching source/harness hashes. Missing isolation, missing/truncated traces and mismatched hashes deny verification.

## Live provider acceptance

| Provider | Observed result | Scope |
| --- | --- | --- |
| Meta | Both `muse-spark-1.3` and `muse-wonder-1.0` online | Mandatory synthesis, runtime policy and deep analysis |
| Anti-Gravity | `gemini-4-argon` online | Independent live reviewer; bounded CLI probes |
| Custom BYOK | `gpt-6-astra`, HTTP 401 | Excluded before pipeline tasks; API integration unit-tested, not live-verified |

Astra caching and tariff support are implemented; no live Astra usage or billing savings are claimed. Unknown provider tariffs remain unknown. Quota fallback is tested with controlled responses; the final live Anti-Gravity probe succeeded on its first selected model.

## Live pipeline acceptance

The final HTTP/WebSocket live run passed all four expected outcomes, receiving 1278 telemetry events across all seven phases.

| Target | Outcome | Run ID |
| --- | --- | --- |
| `cwe_78_cmd.py` | REMEDIATED | `ADHOC-003-42c35dfba604` |
| `cwe_89_sqli.py` | REMEDIATED | `ADHOC-002-7b5304f06dcc` |
| `fp_01.py` | FALSE_POSITIVE | `ADHOC-004-87474558ac65` |
| `poisoned_app.py` | REMEDIATED | `ADHOC-001-887590519c24` |

All three candidate patches passed independent consensus, real CodeShield, original-code positive controls, three neutralized mutations each, regression and live tripwire replay. The benign case was not patched. One ingress injection was sanitized and rescanned. The combined SARIF passes the vendored official SARIF v2.1.0 schema; all three unified diffs pass `git apply --check` and their candidate hashes match the observed regression sandbox evidence.

Earlier denied candidates and inconclusive runs remain archived locally. One regression exposed trace-classification errors: ping's `-c` option was treated as a shell flag, `/dev/null` as an external state change, and the exact local nscd socket as network egress. Executable-based shell detection and precise null-device/name-service classification corrected these errors. Positive-control tests retain rejection of actual shell execution, external writes, unknown sockets and successful exploit probes.

## Evidence locations

Runtime evidence is intentionally ignored by Git and retained locally:

- `reports/live_e2e_verification.json` and `reports/live_e2e_telemetry.json`
- `reports/benchmark_metrics.json` and `reports/agentward_sarif_report.sarif`
- `reports/executive_brief.md` and `reports/executive_brief.html`
- `reports/runs/` for individual run archives, including rejected attempts
- `reports/browser_verification.json`, `reports/live_browser_verification.json`, `reports/release_artifact_verification.json`, `reports/remote_health_verification.json` and `reports/long_ingress_verification.json`
- `patches/<run-id>/` for verified candidates and applicable unified diffs

Benchmark source files remain intentionally vulnerable. Static variant findings and assumptions are follow-up leads, not additional verified remediations. Multi-step storage/decode adapters demonstrate replay robustness; unsupported entry points and failed original-code controls are not counted as neutralized. A compatible filesystem fixture separately exercises the deterministic TOCTOU interleaving.
