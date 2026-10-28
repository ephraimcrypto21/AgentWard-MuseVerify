#!/usr/bin/env python3
import os
import sys
import json
import asyncio
from agentward_stage1 import inspect_file_before_muse
from museverify_stage2 import (
    create_isolated_worktree,
    synthesize_verification_harness,
    run_sandboxed,
    triage_sandbox_result,
    clean_worktrees
)
from agentward_stage3 import AgentWardRuntimeGuard
from museverify_stage4 import synthesize_and_gate_patch
from adversarial_selfplay import run_selfplay
from semantic_hunter import hunt_after_remediation

MAX_PARALLEL_SANDBOXES = 3
sandbox_semaphore = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)

async def run_unified_pipeline(target_file: str, vuln_id: str = "VULN-001"):
    border = "=" * 75
    print("\n" + border)
    print("[*] AGENTWARD + MUSEVERIFY MASTER ORCHESTRATOR")
    print(f"[*] Target: {target_file} | Identifier: {vuln_id}")
    print(border)

    # ---------------------------------------------------------
    # STAGE 1: AgentWard Ingress Sanitization
    # ---------------------------------------------------------
    print("\n[PHASE 1] AgentWard Ingress Sanitization (Pre-Context Shield)...")
    s1_res = inspect_file_before_muse(target_file)
    sanitized_code = s1_res["content"]
    print(f"  └─ Status: {s1_res['status']} | Note: {s1_res.get('reason', 'Clean file')[:80]}...")

    # ---------------------------------------------------------
    # STAGE 2: Worktree Creation & Sandbox Triage
    # ---------------------------------------------------------
    print("\n[PHASE 2] MuseVerify Worktree Fan-Out & Docker Sandbox Triage...")
    wt_dir = create_isolated_worktree(vuln_id, target_file, sanitized_code)
    print(f"  └─ Worktree path: {wt_dir}")

    triage = synthesize_verification_harness(target_file, sanitized_code)
    test_file = os.path.join(wt_dir, "verify_test.py")
    with open(test_file, "w") as f:
        f.write(triage["verification_test_code"])

    print("  └─ Running pre-patch verification in Lightsail Docker sandbox...")
    async with sandbox_semaphore:
        pre_run = await asyncio.to_thread(
            run_sandboxed,
            vuln_id, target_file, sanitized_code, triage["verification_test_code"]
        )
    pre_test_res = triage_sandbox_result(pre_run, target_file)
    print(f"  └─ Sandbox Execution: exit_code={pre_test_res['exit_code']} | "
          f"verdict={pre_test_res['verdict']} | confirmed={pre_test_res['confirmed']}")
    print(f"  └─ Syscall signals: {'; '.join(pre_test_res['signals']) or 'none'}")
    if not pre_test_res["confirmed"]:
        print("[!] Pre-test failed to confirm vulnerability. Halting pipeline.")
        return

    # ---------------------------------------------------------
    # STAGE 3: AgentWard Runtime Hook & Rewind Baseline
    # ---------------------------------------------------------
    print("\n[PHASE 3] AgentWard Runtime Hook & Checkpoint Baseline...")
    guard = AgentWardRuntimeGuard(wt_dir)
    # Perform pre-execution sanity check on tool execution policy
    audit_check = guard.audit_tool_call("bash", f"pytest {test_file}")
    audit_note = audit_check.get("message") or audit_check.get("violation") or "no message"
    print(f"  └─ Tool authorization hook: {audit_check['allowed']} ({audit_note[:100]})")

    # ---------------------------------------------------------
    # STAGE 4: Defensive Patching & CodeShield Gate
    # ---------------------------------------------------------
    print("\n[PHASE 4] Defensive Patch Synthesis & Purple Llama CodeShield...")
    s4_res = await synthesize_and_gate_patch(target_file, simulate_insecure=False)
    if s4_res["status"] != "ACCEPTED":
        print(f"[!] Patch rejected by CodeShield: {s4_res['issues_found']}")
        return

    patched_file = s4_res["patch_path"]
    with open(patched_file, "r") as f:
        patched_code = f.read()
    print(f"  └─ {s4_res.get('tripwire_summary', 'no tripwire synthesized')}")

    # ---------------------------------------------------------
    # STAGE 4.5: Adversarial Self-Play (mutate, replay, gate)
    # ---------------------------------------------------------
    print("\n[PHASE 4.5] Adversarial Self-Play Patch Robustness...")
    selfplay = await run_selfplay(
        target_file, patched_code, sanitized_code,
        triage["sqli_payloads"], triage["cmd_payload"],
        on_event=lambda *_a, **_k: None,
    )
    print(f"  └─ {len(selfplay['survived'])}/{len(selfplay['mutations'])} mutations survived "
          f"({selfplay['source']} mutator)")
    if not selfplay["accepted"]:
        print("[!] Patch defeated by a polymorphic mutation. Halting before regression.")
        return

    # ---------------------------------------------------------
    # REGRESSION CHECK: Re-run Sandbox Against Patched Code
    # ---------------------------------------------------------
    print("\n[PHASE 5] Post-Patch Sandbox Regression Test...")
    async with sandbox_semaphore:
        post_run = await asyncio.to_thread(
            run_sandboxed,
            vuln_id, target_file, patched_code, triage["verification_test_code"]
        )
    post_test_res = triage_sandbox_result(post_run, target_file)
    # The vulnerability test should no longer detect the vulnerability
    remediated = not post_test_res["confirmed"]
    print(f"  └─ Post-Patch Sandbox: exit_code={post_test_res['exit_code']} | "
          f"verdict={post_test_res['verdict']} | bug_still_active={post_test_res['confirmed']}")
    print(f"  └─ Syscall signals: {'; '.join(post_test_res['signals']) or 'none'}")

    if remediated:
        post_clean = clean_worktrees(vuln_id=vuln_id)
        print(f"  └─ Worktree Lifecycle: Cleaned {post_clean['cleaned_count']} temporary harness files ({post_clean['bytes_freed']} bytes freed)")

    # ---------------------------------------------------------
    # POST-REMEDIATION: Semantic Variant Hunting
    # ---------------------------------------------------------
    hunt = {}
    if remediated:
        print("\n[PHASE 5.1] Semantic Variant Hunt Across Codebase...")
        hunt = await hunt_after_remediation(
            target_file, sanitized_code, patched_code,
            os.path.dirname(target_file) or ".",
        )
        print(f"  └─ {len(hunt['matches'])} semantic variant(s) in {hunt['scanned']} file(s)")

    summary = {
        "target_file": target_file,
        "vuln_id": vuln_id,
        "ingress_shield": s1_res["status"],
        "vulnerability_confirmed": pre_test_res["confirmed"],
        "pre_patch_verdict": pre_test_res["verdict"],
        "codeshield_status": s4_res["status"],
        "tripwire": s4_res.get("tripwire"),
        "selfplay_accepted": selfplay["accepted"],
        "selfplay_survived": len(selfplay["survived"]),
        "patch_location": patched_file,
        "regression_verified_fixed": remediated,
        "semantic_variants": hunt.get("matches", []),
    }

    print("\n" + border)
    print("[+] FULL PIPELINE EXECUTION SUMMARY")
    print(border)
    print(json.dumps(summary, indent=2))
    return summary

async def _process_batch_item(idx: int, fpath: str, results: list):
    vuln_id = f"VULN-{idx:03d}"
    print(f"[*] [Batch Queue] Dispatching {vuln_id} ({os.path.basename(fpath)})...")
    try:
        res = await run_unified_pipeline(fpath, vuln_id)
        results.append({"file": fpath, "id": vuln_id, "status": "SUCCESS", "summary": res})
    except Exception as e:
        print(f"[!] [Batch Failure] Error in {vuln_id}: {e}")
        results.append({"file": fpath, "id": vuln_id, "status": "ERROR", "error": str(e)})

async def run_batch_benchmark(targets_dir: str = "benchmark_targets"):
    if not os.path.exists(targets_dir):
        print(f"[!] Directory {targets_dir} does not exist.")
        return []
    target_files = sorted([
        os.path.join(targets_dir, f) for f in os.listdir(targets_dir) 
        if f.endswith(".py")
    ])
    print(f"\n[*] Launching Concurrent Batch Benchmark ({MAX_PARALLEL_SANDBOXES} max parallel sandboxes) over {len(target_files)} target files...\n")
    results = []
    tasks = [
        _process_batch_item(idx, fpath, results)
        for idx, fpath in enumerate(target_files, 1)
    ]
    await asyncio.gather(*tasks)
    print("\n" + "=" * 75)
    print(f"[+] BATCH BENCHMARK COMPLETE: {len(results)} targets processed")
    print("=" * 75)
    return results

if __name__ == "__main__":
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        asyncio.run(run_batch_benchmark(sys.argv[1]))
    else:
        target = sys.argv[1] if len(sys.argv) > 1 else "poisoned_app.py"
        asyncio.run(run_unified_pipeline(target))
