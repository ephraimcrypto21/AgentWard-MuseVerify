#!/usr/bin/env python3
"""
MuseVerify Stage 4.5: Adversarial Patch Robustness (self-play).

A patch that survives the original exploit can still be defeated by a
polymorphic variant of the same payload. Between Phase 4 (CodeShield) and
Phase 5 (regression) the auditor model is asked to mutate the payload, every
mutation is executed against the *patched* sandbox image, and the patch is only
accepted once **all** mutations are neutralized.

Telemetry is pushed through the caller's `on_event` hook so the dashboard can
broadcast mutation-by-mutation results over the existing WebSocket channel.
"""
import asyncio
import json
import os
import re

import museverify_stage2 as stage2

MAX_MUTATIONS = 4

# Deterministic fallbacks keep the loop alive when the model is unreachable.
_FALLBACK_SQLI = [
    "'/**/UNION/**/SELECT/**/1,'AGENTWARD_SQLI'/**/--",
    "' union all select 1,'AGENTWARD_SQLI' #",
    "'%0aUNION%0aSELECT%0a1,'AGENTWARD_SQLI'%0a--",
]

_FALLBACK_CMD = [
    "127.0.0.1&&echo AGENTWARD_CMD>__MARKER__",
    "127.0.0.1|echo AGENTWARD_CMD>__MARKER__",
    "$(echo AGENTWARD_CMD>__MARKER__)",
    "127.0.0.1`echo AGENTWARD_CMD>__MARKER__`",
]


def _fallback_mutations(original_cmd: str) -> dict:
    return {"sqli": list(_FALLBACK_SQLI), "cmd": list(_FALLBACK_CMD)}


async def generate_mutations(
    target_file: str,
    vulnerable_code: str,
    sqli_payloads: list,
    cmd_payload: str,
) -> dict:
    """Ask the auditor model for obfuscated equivalents of the known payload."""
    from ai_provider import query_ai

    prompt = (
        "You are a red-team mutation engine. Below are exploit payloads that "
        "currently break a Python file. Produce semantically identical but "
        "syntactically different mutations that a naive fix might miss "
        "(case changes, comment styles, alternative separators, encoding tricks, "
        "whitespace substitution).\n\n"
        f"SQL injection payloads: {json.dumps(sqli_payloads)}\n"
        f"Command injection payload: {cmd_payload!r}\n"
        "The command payload must keep writing the literal string AGENTWARD_CMD to "
        "the file path placeholder __MARKER__.\n\n"
        "Target file:\n```python\n" + vulnerable_code[:2500] + "\n```\n\n"
        'Reply with ONLY JSON: {"sqli": [string], "cmd": [string]}'
    )
    try:
        raw = await query_ai(
            prompt,
            system_prompt="You are a payload mutation engine. Output only JSON.",
            provider=os.environ.get("AUDITOR_PROVIDER", "meta"), task="selfplay",
        )
        if "```" in raw:
            raw = raw.split("```")[1].replace("json", "", 1).strip()
        start, end = raw.find("{"), raw.rfind("}")
        parsed = json.loads(raw[start:end + 1])
        sqli = [str(p) for p in parsed.get("sqli", []) if str(p).strip()]
        cmd = [str(p) for p in parsed.get("cmd", []) if str(p).strip()]
        if not sqli and not cmd:
            raise ValueError("empty mutation set")
        return {"sqli": sqli[:MAX_MUTATIONS], "cmd": cmd[:MAX_MUTATIONS], "source": "ai",
                "crypto": ["7", "451", "65537"] if "random" in vulnerable_code and any(x in vulnerable_code for x in ("token", "otp", "nonce")) else []}
    except Exception as exc:
        print(f"[!] Stage 4.5 mutation model unavailable ({exc}); using deterministic mutators.")
        fallback = _fallback_mutations(cmd_payload)
        fallback['sqli'] = [p.replace(' UNION SELECT ', '/**/UNION/**/SELECT/**/').replace(' -- ', '/**/--')
                            for p in sqli_payloads][:MAX_MUTATIONS]
        return {**fallback, "source": "fallback", "crypto": ["7", "451", "65537"]
                if "random" in vulnerable_code and any(x in vulnerable_code for x in ("token", "otp", "nonce")) else []}


async def run_selfplay(
    target_file: str,
    patched_code: str,
    vulnerable_code: str = "",
    sqli_payloads: list | None = None,
    cmd_payload: str | None = None,
    on_event=None,
) -> dict:
    """Execute mutated payloads against the patched code.

    Returns {"accepted": bool, "mutations": [...], "survived": [...]}.
    `accepted` is True only when no mutation still proves the bug.
    """
    sqli_payloads = sqli_payloads or stage2.default_sqli_payloads()
    cmd_payload = cmd_payload or stage2.DEFAULT_CMD_PAYLOAD

    if on_event:
        on_event("selfplay_start", {"mutations": 0}, "runtime", "RUNNING", "amber",
                 "Mutating exploit payload for adversarial replay")

    mutated = await generate_mutations(target_file, vulnerable_code, sqli_payloads, cmd_payload)
    print(f"[MuseVerify Stage-4.5] Generated {len(mutated['sqli'])} SQLi / "
          f"{len(mutated['cmd'])} cmd mutations ({mutated['source']}).")

    results = []
    survived = []

    for kind in ("sqli", "cmd", "crypto"):
        for index, payload in enumerate(mutated[kind], 1):
            harness = stage2.synthesize_verification_harness(
                target_file, patched_code,
                sqli_payloads=[payload] if kind == "sqli" else sqli_payloads,
                cmd_payload=payload if kind == "cmd" else cmd_payload,
            )
            if kind == 'crypto':
                harness['verification_test_code'] = harness['verification_test_code'].replace('random.seed(451)', f'random.seed({int(payload)})')
            # Limit model-generated payloads before any local fallback execution.
            if kind == 'cmd' and (len(payload) > 2048 or 'AGENTWARD_CMD' not in payload or '__MARKER__' not in payload
                                  or re.search(r'\b(?:curl|wget|rm|chmod|mkfs|dd|nc|python|bash)\b|https?://', payload, re.I)):
                results.append({'kind': kind, 'payload': payload, 'verdict': 'INCONCLUSIVE', 'penetrated': False,
                                'viable': False, 'neutralized': False, 'inconclusive': True, 'signals': ['Unsafe mutation rejected']})
                continue
            baseline = await asyncio.to_thread(
                stage2.run_sandboxed, f"selfplay-baseline-{kind}-{index}", target_file,
                vulnerable_code, harness["verification_test_code"])
            baseline_triage = stage2.triage_sandbox_result(baseline, target_file)
            prefix = {"sqli": "sqli_union", "cmd": "cmd:", "crypto": "weak_prng:"}[kind]
            viable = any(p.get("ok") and str(p.get("probe", "")).startswith(prefix)
                         for p in baseline_triage.get("probes", []))
            run = await asyncio.to_thread(
                stage2.run_sandboxed,
                f"selfplay-{kind}-{index}", target_file, patched_code,
                harness["verification_test_code"],
            )
            triage = stage2.triage_sandbox_result(run, target_file)
            penetrated = triage["verdict"] == "EXPLOITABLE" or triage["confirmed"]
            record = {
                "kind": kind,
                "payload": payload,
                "verdict": triage["verdict"],
                "evasion_score": triage["evasion_score"],
                "penetrated": penetrated,
                "viable": viable,
                "neutralized": viable and triage["safe"],
                "inconclusive": not triage["execution_valid"] or not baseline_triage["execution_valid"],
                "signals": triage["signals"],
            }
            results.append(record)
            if penetrated:
                survived.append(record)
            print(f"  └─ [{kind} {index}] {payload[:60]!r} -> {triage['verdict']}"
                  f"{' (PATCH BYPASSED)' if penetrated else ''}")
            if on_event:
                on_event(
                    "selfplay_mutation",
                    {**record, "index": index},
                    "runtime",
                    "FAIL" if penetrated else "OK",
                    "red" if penetrated else "emerald",
                    f"{kind} mutation {index}: {triage['verdict']}",
                )

    accepted = any(r["viable"] for r in results) and not survived and not any(r["inconclusive"] for r in results)
    neutralized = [r for r in results if r["neutralized"]]
    if on_event:
        on_event(
            "selfplay_result",
            {"accepted": accepted, "total": len(results), "survived": len(survived)},
            "runtime", "PASS" if accepted else "FAIL",
            "emerald" if accepted else "red",
            "All mutations neutralized" if accepted else f"{len(survived)} mutation(s) still exploit the patch",
        )
    return {"accepted": accepted, "mutations": results, "survived": survived,
            "source": mutated["source"], "neutralized": neutralized,
            "not_viable": sum(not r["viable"] for r in results),
            "inconclusive": sum(r["inconclusive"] for r in results)}
