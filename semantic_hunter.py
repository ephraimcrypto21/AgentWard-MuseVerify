#!/usr/bin/env python3
"""
MuseVerify post-remediation: Semantic Variant Hunting.

Stage 5 can only prove that *one* file was fixed. The same root cause usually
survives elsewhere in the tree in a structurally different shape (a `%`-format
query instead of an f-string, `os.popen` instead of `os.system`, ...). AST queries
miss those. Here the auditor model:

  1. distills the semantic root cause (taint source -> sink -> missing control)
     from the vulnerable/patched pair, then
  2. sweeps a corpus of sibling files for code that is syntactically unrelated
     but semantically identical.

Everything is reported through the caller's `on_event` hook, so the dashboard
streams the hunt over the existing WebSocket channel.
"""
import asyncio
import ast
import json
import os
import re

MAX_CANDIDATE_FILES = 40
MAX_FILE_CHARS = 2000

# Root-cause families keep a lexical fallback alive when the model is offline.
ROOT_CAUSE_FAMILIES = {
    "sqli": {
        "label": "SQL string interpolation",
        "tokens": (r"\bexecute\s*\(\s*f[\"']", r"\bexecute\s*\([^)]*%", r"\.format\(",
                   r"\"\s*\+|\+\s*\"", r"\bexecutemany\s*\("),
        "indicators": ("select", "insert", "update", "delete", "where", "cursor.execute"),
    },
    "cmd": {
        "label": "shell command interpolation",
        "tokens": (r"\bos\.system\s*\(", r"\bos\.popen\s*\(", r"shell\s*=\s*True",
                   r"subprocess\.(?:call|run|Popen|check_output)\s*\("),
        "indicators": ("subprocess", "os.system", "popen", "shell=true", "&&", "|"),
    },
    "crypto": {
        "label": "non-cryptographic randomness",
        "tokens": (r"\brandom\.(?:random|randint|choice|choices|sample)\s*\(",
                   r"\bfrom\s+random\s+import\b"),
        "indicators": ("token", "secret", "csrf", "nonce", "session", "salt", "password"),
    },
    "secrets": {
        "label": "static credential material",
        "tokens": (r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|DSN)\w*\s*=\s*[\"']",),
        "indicators": ("api_key", "token", "secret", "credential"),
    },
}

_SEVERITY = ("EXPLOITABLE", "SUSPICIOUS", "INFO")


# ---------------------------------------------------------------------------
# Root-cause extraction
# ---------------------------------------------------------------------------
def _classify(text: str) -> str:
    """Best-effort family for a block of code (used by the offline fallback)."""
    lowered = text.lower()
    best, best_score = None, 0
    for family, spec in ROOT_CAUSE_FAMILIES.items():
        score = sum(1 for token in spec["tokens"] if re.search(token, text)) * 2
        score += sum(1 for word in spec["indicators"] if word in lowered)
        if score > best_score:
            best, best_score = family, score
    return best or "unknown"


def _fallback_root_cause(target_file: str, vulnerable_code: str) -> dict:
    family = _classify(vulnerable_code)
    spec = ROOT_CAUSE_FAMILIES.get(family)
    return {
        "family": family,
        "root_cause": (
            f"Untrusted input reaches a {spec['label']} sink without escaping or "
            "parameterization." if spec else
            "Untrusted input reaches a dangerous sink without a compensating control."
        ),
        "semantic_signature": ", ".join(spec["tokens"]) if spec else "",
        "indicators": list(spec["indicators"]) if spec else [],
        "source": "fallback",
    }


async def extract_root_cause(target_file: str, vulnerable_code: str, patched_code: str,
                             on_event=None) -> dict:
    """Distill *why* the file was vulnerable, independent of its exact syntax."""
    from ai_provider import query_ai

    if on_event:
        on_event("hunter_root_cause", {"file": os.path.basename(target_file)},
                 "remediation", "RUNNING", "violet",
                 "Extracting semantic root cause of the vulnerability")

    prompt = (
        "You are a vulnerability taxonomist. A file was vulnerable and has now been "
        "patched. Describe the *semantic* root cause so that a sibling file written in a "
        "completely different style can still be recognized as the same bug.\n\n"
        "Ignore naming, formatting and library choice. Capture: taint source, sink, and "
        "the missing control.\n\n"
        f"VULNERABLE:\n```python\n{vulnerable_code[:2500]}\n```\n\n"
        f"PATCHED:\n```python\n{patched_code[:2500]}\n```\n\n"
        "Reply with ONLY JSON: "
        '{"family": "sqli|cmd|crypto|secrets|other", "root_cause": string, '
        '"semantic_signature": string, "indicators": [string]}'
    )
    try:
        raw = await query_ai(
            prompt,
            system_prompt="You are a vulnerability taxonomist. Output only JSON.",
            provider=os.environ.get("AUDITOR_PROVIDER", "meta"),
        )
        if "```" in raw:
            raw = raw.split("```")[1].replace("json", "", 1).strip()
        start, end = raw.find("{"), raw.rfind("}")
        parsed = json.loads(raw[start:end + 1])
        family = str(parsed.get("family", "other")).lower()
        root_cause = str(parsed.get("root_cause", "")).strip()
        if not root_cause:
            raise ValueError("empty root cause")
        result = {
            "family": family if family in ROOT_CAUSE_FAMILIES else _classify(vulnerable_code),
            "root_cause": root_cause,
            "semantic_signature": str(parsed.get("semantic_signature", "")),
            "indicators": [str(i) for i in parsed.get("indicators", [])][:12],
            "source": "ai",
        }
    except Exception as exc:
        print(f"[!] Hunter root-cause model unavailable ({exc}); using classifier fallback.")
        result = _fallback_root_cause(target_file, vulnerable_code)

    print(f"[MuseVerify Hunter] root cause ({result['family']}): {result['root_cause'][:120]}")
    if on_event:
        on_event("hunter_root_cause", result, "remediation", "OK", "violet",
                 f"Root cause: {result['root_cause'][:100]}")
    return result


# ---------------------------------------------------------------------------
# Corpus sweep
# ---------------------------------------------------------------------------
def _syntax_ok(text: str) -> bool:
    try:
        ast.parse(text)
        return True
    except SyntaxError:
        return False


def _collect_corpus(corpus_dir: str, exclude: str) -> list:
    files = []
    for name in sorted(os.listdir(corpus_dir)):
        path = os.path.join(corpus_dir, name)
        if not os.path.isfile(path) or not name.endswith(".py"):
            continue
        if os.path.abspath(path) == os.path.abspath(exclude):
            continue
        files.append(path)
        if len(files) >= MAX_CANDIDATE_FILES:
            break
    return files


def _lexical_score(text: str, root_cause: dict) -> int:
    family = root_cause.get("family")
    spec = ROOT_CAUSE_FAMILIES.get(family)
    score = 0
    if spec:
        score += sum(2 for token in spec["tokens"] if re.search(token, text))
    lowered = text.lower()
    score += sum(1 for word in root_cause.get("indicators", []) if word.lower() in lowered)
    return score


def _fallback_hunt(corpus: dict, root_cause: dict) -> list:
    matches = []
    for path, text in corpus.items():
        if not _syntax_ok(text):
            continue
        score = _lexical_score(text, root_cause)
        if score < 3:
            continue
        matches.append({
            "file": os.path.basename(path),
            "severity": "SUSPICIOUS" if score < 6 else "EXPLOITABLE",
            "score": score,
            "reason": f"Lexically matches the {root_cause.get('family')} root-cause family",
        })
    return sorted(matches, key=lambda m: m["score"], reverse=True)


async def hunt_variants(root_cause: dict, corpus_dir: str, exclude_file: str = "",
                        on_event=None) -> dict:
    """Scan `corpus_dir` for structurally different, semantically identical bugs."""
    from ai_provider import query_ai

    paths = _collect_corpus(corpus_dir, exclude_file)
    corpus = {}
    for path in paths:
        try:
            with open(path, "r") as handle:
                corpus[path] = handle.read()[:MAX_FILE_CHARS]
        except OSError:
            continue
    print(f"[MuseVerify Hunter] scanning {len(corpus)} sibling file(s) in {corpus_dir}")

    if on_event:
        on_event("hunter_scan", {"files": len(corpus), "corpus": os.path.basename(corpus_dir)},
                 "remediation", "RUNNING", "violet", f"Scanning {len(corpus)} sibling files")

    bundle = "\n\n".join(f"=== {os.path.basename(p)} ===\n{t}" for p, t in corpus.items())
    prompt = (
        "Hunt for semantic variants of a known root cause across a codebase.\n\n"
        f"ROOT CAUSE ({root_cause.get('family')}): {root_cause.get('root_cause')}\n"
        f"Signature: {root_cause.get('semantic_signature')}\n"
        f"Indicators: {', '.join(root_cause.get('indicators', []))}\n\n"
        "A variant is a DIFFERENT file that reaches the same sink from untrusted input "
        "with the same missing control, even if it uses another API, quoting style or "
        "helper. Benign lookalikes (parameterized queries, argv-list subprocess, secrets "
        "module) must NOT be reported. Only report files present in the bundle.\n\n"
        f"{bundle}\n\n"
        "Reply with ONLY JSON: "
        '{"matches": [{"file": string, "severity": "EXPLOITABLE|SUSPICIOUS", "reason": string}]}'
    )
    try:
        raw = await query_ai(
            prompt,
            system_prompt="You are a semantic vulnerability hunter. Output only JSON.",
            provider=os.environ.get("AUDITOR_PROVIDER", "meta"),
        )
        if "```" in raw:
            raw = raw.split("```")[1].replace("json", "", 1).strip()
        start, end = raw.find("{"), raw.rfind("}")
        parsed = json.loads(raw[start:end + 1])
        known = {os.path.basename(p) for p in corpus}
        matches = []
        for item in parsed.get("matches", []):
            name = os.path.basename(str(item.get("file", "")))
            if name not in known:
                continue
            severity = str(item.get("severity", "SUSPICIOUS")).upper()
            matches.append({
                "file": name,
                "severity": severity if severity in _SEVERITY else "SUSPICIOUS",
                "reason": str(item.get("reason", "semantic variant"))[:200],
            })
        source = "ai"
    except Exception as exc:
        print(f"[!] Hunter scan model unavailable ({exc}); using lexical fallback.")
        matches = _fallback_hunt(corpus, root_cause)
        source = "fallback"

    matches.sort(key=lambda m: _SEVERITY.index(m["severity"]))
    for match in matches:
        print(f"  └─ {match['file']}: {match['severity']} ({match['reason'][:70]})")
        if on_event:
            on_event("hunter_match", match, "remediation",
                     "FAIL" if match["severity"] == "EXPLOITABLE" else "WARN",
                     "red" if match["severity"] == "EXPLOITABLE" else "amber",
                     f"Variant: {match['file']} — {match['reason'][:80]}")

    result = {"root_cause": root_cause, "matches": matches, "scanned": len(corpus),
              "source": source}
    if on_event:
        on_event("hunter_result",
                 {"matches": len(matches), "scanned": len(corpus)},
                 "remediation", "PASS" if not matches else "WARN",
                 "emerald" if not matches else "amber",
                 "No semantic variants found" if not matches
                 else f"{len(matches)} semantic variant(s) require review")
    return result


async def hunt_after_remediation(target_file: str, vulnerable_code: str, patched_code: str,
                                 corpus_dir: str = "benchmark_targets", on_event=None) -> dict:
    """Convenience entry point: extract the root cause, then sweep the corpus."""
    root_cause = await extract_root_cause(target_file, vulnerable_code, patched_code,
                                          on_event=on_event)
    return await hunt_variants(root_cause, corpus_dir, exclude_file=target_file,
                               on_event=on_event)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "benchmark_targets/cwe_78_cmd.py"
    corpus = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(target) or "."
    with open(target, "r") as fh:
        vuln = fh.read()
    print(json.dumps(asyncio.run(hunt_after_remediation(target, vuln, vuln, corpus)), indent=2))
