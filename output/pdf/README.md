# Project guide: reviewed 1 November 2026

[PDF guide](AgentWard_MuseVerify_Project_Guide.pdf) · [HTML companion](AgentWard_MuseVerify_Project_Guide.html)

The **20-page PDF** and HTML companion explain application snapshot
**`2d52f29a585abf5c4dc241bdda118b5834c63126`**. This edition replaces the
31 October guide and includes the completed live Node corpus acceptance.
Both formats are generated from the same reviewed content in
[tools/build_project_guide.py](../../tools/build_project_guide.py).

The guide covers the problem and core rule, architecture and trust boundaries,
all seven phases, Python/JavaScript/TypeScript contracts, runtime policy and
rewind, Meta-primary ensembles, BYOK configuration, Linux deployment, SSH and
Tailscale connectivity, the dashboard API, artifacts, skill provenance and
verification limits. Pages 17–18 separate current live results from historical
classifier and protocol checks and list all 13 Node outcomes.

## Evidence scope

The 1 November application acceptance records **99 tests passed with no skips**,
**8 live remediations**, **4 false-positive controls**, **1 inconclusive CWE-338
finding**, and **24 neutralized Node self-play scenarios with zero survivors**.
The latest live repairs used Meta Spark and Wonder, real ingress and authenticated
remote Docker. The 78/78 classifier cases and 25 remote acceptance groups retain
their earlier dates and scope; the classifier sets were used during development,
and the older remote repair controls used fixtures.

The guide does not claim industry-wide triage rates, universal detection
accuracy, kernel interception by the application policy hook, whole-project
TypeScript support or production-wide proof from finite regression probes.
Model votes are required but cannot waive deterministic evidence checks.

## Rebuild both formats

From the repository root, in a Python environment of your choice:

```bash
python -m pip install -r requirements-docs.txt
python tools/build_project_guide.py
```

The default command updates the published PDF and HTML files in `output/pdf/`.
To produce the requested convenience copies in the repository root with one
command after installing the optional dependency:

```bash
python tools/build_project_guide.py --output AgentWard_MuseVerify_Project_Guide.pdf
```

`--output` must name a `.pdf`; the companion uses the same stem with `.html`.
The root copies are ignored by Git to avoid duplicating the published artifacts.
No browser, TeX installation, provider connection or verification-node call is
needed to build the files.

ReportLab uses embedded Lato and DejaVu Sans Mono when their standard Linux font
files are available, with standard PDF fonts as a fallback. Matching fonts and
dependencies produce deterministic output. A page-count check requires layout
review if content or fonts change; outputs are staged before replacing the
published files. Rebuilding documents does not establish fresh live acceptance.

## Review performed for this edition

- Rendered all 20 PDF pages and inspected typography, diagram labels, tables,
  code wrapping, footer spacing and page numbering.
- Checked PDF text and metadata, all 19 outline destinations, versioned source
  links and text bounds. Root and published copies match byte-for-byte after
  separate builds.
- Loaded the HTML in Chromium at 1440-pixel desktop and 390-pixel phone widths:
  20 sections, no page errors, no broken internal links and no horizontal page
  overflow. Checked navigation to the architecture section.
- Validated README local links and Bash example syntax against the repository.
- Ran the 99-test discovery suite with real Docker: **99 passed, zero skipped**
  in 73.120 seconds. Ruff correctness checks, dependency consistency and the
  **818-skill integrity check** passed. These documentation checks do not replace
  the separately recorded live-provider corpus acceptance.

The PDF contains searchable text, outline bookmarks, an internal reading map and
versioned source links. The HTML provides semantic sections, table headers and
responsive layouts. No credentials, private deployment addresses or provider
transcripts are embedded. PDF files are marked binary in `.gitattributes` so
Git does not treat PDF format whitespace as source-code defects.
