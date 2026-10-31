# Source-aware ingress guard

The old `Niansuh/Prompt-Guard-86M` classifier treated ordinary Python and Node
syntax as injected instructions, including `cwe_78_cmd.js` and `fp_node.mjs`.
Ingress now uses
[Horizon Labs Prompt Injection Guard Small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small)
at revision `5ed691c28fc37db51f4e80fb81311b7d2b5d4646`, under Apache-2.0.
Meta remains mandatory for the later synthesis, policy and review stages.

## Classification contract

`ingress_guard.py` prepends bounded parser facts: the source language, declared
names and syntax-node kinds. These facts explain code structure, without claiming
that the code is safe. The complete unchanged source follows that context.
There are no filename exemptions, source allowlists or automatic approvals based
on valid syntax.

Every input is scanned in overlapping 512-token windows with 128-token overlap.
Any window can veto acceptance at the existing 0.40 risk threshold. The sanitizer
also recognizes explicit role-directed instructions to bypass security controls
or fabricate audit results inside comments/literals, including decoded base64.
This catches those directives even when repeated documentation dilutes the
learned detector's score. Sanitized source receives its own complete model scan.

The guard permits at most 256 inference windows per original or sanitized input.
Inputs exceeding that work bound return incomplete evidence and remain denied;
no text is silently truncated. Failed parsing, missing model files, hash
mismatches, invalid/nonfinite probabilities and inference errors also fail closed.

`security/ingress-model.lock.json` pins the revision and SHA-256 hashes of all
five loaded artifacts. Loading exposes only verified files to Transformers,
uses safetensors, disables remote code and performs no network downloads during
inference. Model provisioning is an explicit deployment step.

Responses use backend `injection_guard` and include a version-2 classifier
contract binding model identity and the classification policy. The workstation
requires an exact match plus language and original/sanitized hashes. Old
`prompt_guard` responses cannot establish evidence. Sandbox protocol v3 is
unchanged. A classified attack reports `BLOCKED`; unavailable or mismatched
evidence reports `UNVERIFIED`.

## Reproduce validation

Install `requirements-node.txt` in the node environment, then provision the model:

```bash
python tools/manage_ingress_model.py install
python tools/manage_ingress_model.py verify
python tools/evaluate_ingress_guard.py --output reports/ingress-regression.json
python tools/evaluate_ingress_guard.py --cases tests/data/ingress_holdout.json \
  --output reports/ingress-additional.json
python tools/evaluate_ingress_guard.py --cases tests/data/ingress_context_attacks.json \
  --output reports/ingress-context-attacks.json
```

These checks perform real local inference and never execute submitted source.
The 78 cases comprise 45 benign inputs and 33 malicious instruction inputs.
All 78 passed on the authorized node in an isolated staging checkout on
31 October 2026. The full 91-test suite passed with real Docker and no skips;
an additional corpus-validity test also passed, bringing the total to 92.
Benign cases must remain unchanged and pass. Malicious cases must be blocked or
sanitized and successfully rescanned. The corpora include the reported Node
failures, ordinary object literals/exports, multilingual instructions, base64,
instructions after the first window, and attacks surrounded by innocuous parser
context or repeated documentation. The additional sets were used during policy
development; these are regression results, not estimates on an untouched test set.

Unit tests separately cover stale policy/model responses, source tampering,
sanitizer rescans, incomplete windows, nonfinite model output, corrupt cached
artifacts and inference failures. The full pipeline and Docker suites retain
their model fixtures; they do not replace these real-classifier checks.

## Deployment

Upgrade the ingress service and workstation together. The deployment script now
installs all node requirements and provisions/verifies the pinned model before
restarting services. Restart the dashboard to load the matching classifier
contract. The existing node token, private tailnet connectivity, sandbox image
and runtime verification gates remain in use.

This is a learned detector with measured regression coverage, not a proof of
perfect precision or recall on arbitrary source. Parser context never grants
tool permissions; runtime isolation, mandatory model review, CodeShield and
regression evidence remain separate requirements.
