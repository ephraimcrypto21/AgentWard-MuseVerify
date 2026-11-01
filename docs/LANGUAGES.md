# Language adapters

Added 31 October 2026. `language_adapters.py` is the source-language registry for
Python, JavaScript and TypeScript. Each adapter supplies parsing, ingress
sanitization, public-contract inspection and structural tripwire validation.
The orchestrator keeps one seven-phase pipeline, one policy session, and the same
evidence/reporting gates for all supported languages.

## Supported source

Python retains its existing behavior. Node adapters accept `.js`/`.cjs` CommonJS,
`.js`/`.mjs` ES modules, and `.ts`/`.mts`/`.cts` TypeScript according to Node 24's
module rules. They support top-level named exported functions and arrow functions,
including `module.exports = {functionName}` and `exports.functionName = function`.
The current probes require a single scalar argument and a serializable return
value. All exported functions must be compatible SQL/command entry points, at
most eight per target; partial or ambiguous probe coverage is rejected.

The corpus covers all six Node extensions: eight vulnerable command/SQL targets,
four benign controls, and a weak-randomness target with a supported SQL entry
point. It includes aliased shell calls, SQL `LIKE` and authentication queries,
bound parameters, safe argument arrays, interfaces, generics and type assertions.
See the complete [1 November corpus acceptance](CORPUS_ACCEPTANCE_2026-11-01.md).

Every export must return successfully for `agentward_normal` inside the
network-disabled sandbox. `cwe_78_cmd_ping.cts` retains its `pingHost` API and
intentional shell interpolation but echoes the diagnostic host with `printf`;
it requires neither a `ping` executable nor DNS/network access. This keeps its
normal baseline reproducible without removing the vulnerability.

Choose a benchmark in the dashboard or enter another source path within the
workspace. CLI and `POST /api/run` use the same adapters. Batch mode includes all
supported extensions. `GET /api/languages` reports the registry and scope.

## Verification behavior

1. Tree-sitter parses JavaScript/TypeScript without importing or executing it.
   Hostile comments/simple string literals can be sanitized; the remote
   pinned ingress classifier must verify the full sanitized source and its hashes,
   together with its model/policy identity. Parser context helps distinguish code
   structure from embedded instructions; it never substitutes for the source scan.
2. Deterministic Node harnesses import the source only inside Docker. They check
   normal returns and fire SQL or command-injection probes. Exceptions, absent
   exports and missing normal results cannot establish successful execution.
   Harness metadata identifies the covered CWEs. When these probes find no
   exploit, a static finding outside their CWE coverage remains `INCONCLUSIVE`
   and is retained in `unverified_findings`. In particular, safe SQL execution
   cannot dismiss a `Math.random()` token finding (CWE-338).
3. Existing runtime policy and independent model reviewers remain mandatory.
   Benign controls finish as `FALSE_POSITIVE` after the Phase 2 result and
   mandatory Phase 3 policy review; patch synthesis and Phases 4–5.1 are skipped.
4. Patch gates preserve exported parameter/type and sync/async signatures, require
   an AST-recognized equality guard and `console.warn`/`console.error` tripwire,
   review static findings, and run CodeShield's JavaScript rules. TypeScript's
   type-only nodes are erased before scanning, then parsed as JavaScript; the
   original TypeScript remains the candidate used for all sandbox tests.
5. Node self-play runs deterministic syntax mutations and storage/URL replay
   adapters against original and patched source. Every scenario requires a
   successful original-code positive control and complete protected evidence.
6. Regression compares normal return values with the original baseline, replays
   the exploit, and verifies the tripwire fires only for the fake canary.
7. Semantic hunting includes JavaScript/TypeScript siblings, static call paths and
   explicit coverage limits. SARIF records the source language and keeps simulated
   outcomes separate from verified production repairs.

## Limits and failure results

- **`UNSUPPORTED_LANGUAGE`**: extension outside the registry, including Java,
  Go, Rust, JSX and TSX. The dashboard returns HTTP 422 with this code; CLI runs
  record the same outcome before contacting providers or executing source.
- **`INVALID_SOURCE`**: invalid syntax for the selected language.
- **`UNSUPPORTED_TARGET`**: no compatible Node SQL/command probe entry point after
  ingress. This is not a benign finding.
- Browser applications, classes requiring construction, multi-file execution,
  npm dependencies, transpiler plugins, project builds and arbitrary compiler
  configurations are not supported. Missing imports or incompatible execution
  return failed/inconclusive evidence.
- TypeScript support covers erasable syntax such as annotations, interfaces,
  type aliases, generics and `as` assertions. It does not run a type checker.
  Enums, namespaces, decorators and unsupported transformations cannot pass the
  complete verification chain.
- ECMAScript static taint is intraprocedural. Import aliases, closures, dynamic
  dispatch and cross-file propagation are reported as limits requiring independent
  review; the Python graph's broader propagation is not claimed for Node.
- CodeShield's JavaScript rule set has narrower coverage than a complete security
  audit. A clean scan supplements AST checks, model review and runtime tests.
- Node normal regression currently uses the deterministic `agentward_normal`
  input. Other business contracts require additional adapter probes.
- Node code always requires Docker, even with fixture models. Setting
  `AGENTWARD_FORCE_LOCAL=1` never enables host execution for Node.

## Deployment

Install the updated Python requirements on the workstation and ingress node.
Deploy the full source checkout, then build `security/Dockerfile.sandbox` as
`agentward-sandbox:multilang-v3`. It combines Python 3.12, official Node 24 and
strace. The existing shared token and Linux/POSIX-ACL requirements still apply.

Protocol **v3** adds language/runtime/filename binding to protected trace and
artifact hashes. Upgrade both node services, the image, and workstation together;
v2 responses are rejected. No arbitrary interpreter commands can be supplied by
the caller. Runtime selection is a fixed `python3`/`node` allowlist, and the
bootstrap drops UID/GID/groups before either language executes submitted source.

## Validation

Current corpus acceptance, **1 November 2026**: **99 tests passed with no skips**,
including real Docker suites. All 13 Node targets parsed and received real
classifier `ALLOW`; all six TypeScript targets passed erasure and JavaScript
scanning. Live Meta/remote Docker runs produced eight verified repairs, four
false-positive controls and one correctly retained inconclusive CWE-338 case.
The [acceptance record](CORPUS_ACCEPTANCE_2026-11-01.md) documents retries,
artifacts, scope and remaining limits.

Historical adapter acceptance, **31 October 2026**: **81 tests passed with no skips**: the 80-test full suite,
including both real Docker suites, plus an additional `.cjs`/`.cts`/`.mts`
module-extension acceptance test. Browser acceptance completed JavaScript and TypeScript runs through the
source-path field, confirmed the unsupported-language error, and reported zero
page errors. Ruff, dependency consistency and deployment-script syntax checks passed.

Run the ordinary suite plus the real Docker and corpus suites:

```bash
python -m unittest discover -v
docker build -t agentward-sandbox:multilang-v3 -f security/Dockerfile.sandbox .
AGENTWARD_TEST_DOCKER=1 SANDBOX_IMAGE=agentward-sandbox:multilang-v3 \
  python -m unittest tests.test_docker_security tests.test_multilanguage_docker tests.test_benchmark_corpus -v
```

The new tests cover parsing/sanitization, TypeScript erasure, module contracts,
false tripwire markers, policy restrictions, source-language binding, unsupported
extensions, scanner failures, real Node isolation, SQL/command positive controls,
normal/tripwire regression, missing dependencies and complete seven-phase runs.
Model/ingress fixtures are labeled as simulation; these tests do not claim live
Meta or remote Prompt-Guard acceptance. The subsequent coordinated remote upgrade
and live node acceptance are recorded in [DEPLOYMENT_V3.md](DEPLOYMENT_V3.md).
