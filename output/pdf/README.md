# Current-stage project guide

[AgentWard_MuseVerify_Project_Guide.pdf](AgentWard_MuseVerify_Project_Guide.pdf)
is the 16-page edition reviewed on **31 October 2026**, describing application
release **59f8c1dac5cfde863d4e9ed62303b9f9e09ffc73**. It replaces the older
Python-only guide based on snapshot 99ac51a.

It covers the deployed architecture, seven phases, Python/JavaScript/TypeScript
target contracts, source-aware ingress guard, protected protocol-v3 runtime
evidence, provider modes, operator workflow, APIs, skill integration and
verification limits. Page 6 explains probabilistic detection in plain language;
page 14 distinguishes real classifier checks, remote Docker acceptance,
fixture repairs and historical live-provider results.

The guide is a fixed evidence snapshot. Rebuilding it does not query services,
revalidate providers or establish new live acceptance. The 78 classifier cases
were used during policy development; they are regression evidence rather than
an untouched holdout accuracy estimate. The latest deployment checks did not
repeat full live model-generated seven-phase remediation.

## Rebuild

From the repository root, in a Python environment of your choice:

```bash
python -m pip install -r requirements-docs.txt
python tools/build_project_guide.py
```

An alternate path can be supplied with `--output /path/to/guide.pdf`.
The generator uses embedded Lato and DejaVu Sans Mono when their standard Linux
font files are available, with standard PDF fonts as a fallback. Identical
dependencies and fonts produce deterministic output; fallback fonts may require
layout review. A page-count check prevents publishing an unexpected layout and
the final PDF is replaced only after a successful build.

The maintained content and vector architecture diagram are in
[`tools/build_project_guide.py`](../../tools/build_project_guide.py). Review the
source documents and evidence ledger when changing its date or application
revision; do not simply stamp a newer Git revision onto old results. The PDF
contains outline bookmarks, an internal reading map and versioned source links.
No credentials, deployment addresses or private runtime reports are embedded.

## Review performed for this edition

- Rendered all 16 pages and checked typography, wrapping, diagram labels,
  footer spacing and page numbering.
- Checked extracted text, metadata, PDF links and evidence claims against the
  versioned docs and locally retained acceptance records.
- Documentation-change checks: the 92-test discovery suite completed with
  82 passed and 10 opt-in Docker tests skipped; Ruff correctness checks and
  `pip check` passed. These checks do not replace the prior real-Docker release
  acceptance described in the guide.
