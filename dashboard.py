import os
import json
import asyncio
import itertools
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from agentward_stage1 import inspect_file_before_muse
from museverify_stage2 import (
    create_isolated_worktree,
    synthesize_verification_harness,
    run_sandboxed,
    triage_sandbox_result_async,
    describe_syscall_trail,
    clean_worktrees
)
from agentward_stage3 import AgentWardRuntimeGuard
from museverify_stage4 import synthesize_and_gate_patch
from adversarial_selfplay import run_selfplay
from semantic_hunter import hunt_after_remediation
from ai_provider import ACTIVE_PROVIDER

app = FastAPI(title="AgentWard + MuseVerify Cockpit")

MAX_PARALLEL_SANDBOXES = 3
sandbox_semaphore = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)
_adhoc_seq = itertools.count(1)

class AuditRequest(BaseModel):
    target_file: str

class CleanRequest(BaseModel):
    remove_all: bool = False

active_connections = []
background_tasks = set()

def make_emitter(default_phase: float = 0, default_color: str = "slate"):
    """Adapt module-level sync callbacks onto the async broadcast channel."""
    def emit(event_type: str, data=None, phase: float | int = "", status: str = "",
             color: str = "", note: str = ""):
        phase_no = phase if isinstance(phase, (int, float)) and phase else default_phase
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        task = asyncio.create_task(
            broadcast(event_type, data or "", phase_no,
                      status=status, color=color or default_color, note=note)
        )
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
    return emit

async def broadcast(event_type: str, data: str = "", phase: int = 0, status: str = "", color: str = "", note: str = ""):
    payload = json.dumps({"type": event_type, "data": data, "phase": phase, "status": status, "color": color, "note": note})
    for ws in list(active_connections):
        try:
            await ws.send_text(payload)
        except Exception:
            if ws in active_connections:
                active_connections.remove(ws)

@app.get("/", response_class=HTMLResponse)
async def get_index():
    template = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "index.html")
    with open(template) as f:
        return f.read()

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)

@app.post("/api/run")
async def run_pipeline_api(req: AuditRequest):
    task = asyncio.create_task(execute_harness(req.target_file, f"ADHOC-{next(_adhoc_seq):03d}"))
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return {"status": "started", "file": req.target_file}

@app.post("/api/clean")
async def clean_workspaces_api(req: CleanRequest = CleanRequest()):
    res = clean_worktrees(vuln_id=None, remove_all=req.remove_all)
    await broadcast(
        "log",
        f"[Lifecycle] Workspace clean completed: {res['cleaned_count']} temporary files pruned ({res['bytes_freed']} bytes freed)."
    )
    return {"status": "success", "result": res}

@app.post("/api/batch")
async def run_batch_api():
    task = asyncio.create_task(run_batch_benchmark_dashboard())
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return {"status": "started", "concurrency": MAX_PARALLEL_SANDBOXES}

async def run_batch_benchmark_dashboard(targets_dir: str = "benchmark_targets"):
    await broadcast("log", f"[*] Starting Concurrent Batch Stress Test ({MAX_PARALLEL_SANDBOXES} parallel sandboxes)...")
    if not os.path.exists(targets_dir):
        await broadcast("log", f"[!] Targets directory {targets_dir} not found.")
        return
    target_files = sorted([
        os.path.join(targets_dir, f) for f in os.listdir(targets_dir) 
        if f.endswith(".py")
    ])
    async def process_one(idx, fpath):
        vid = f"VULN-{idx:03d}"
        await broadcast("log", f"[*] [Batch Dispatch] Running {vid}: {fpath}...")
        await execute_harness(fpath, vid)

    tasks = [process_one(idx, fpath) for idx, fpath in enumerate(target_files, 1)]
    await asyncio.gather(*tasks)
    await broadcast("log", f"[+] BATCH STRESS TEST COMPLETED: {len(target_files)} alerts evaluated.")

async def execute_harness(target_file: str, vuln_id: str = "VULN-001"):
    try:
        # Pre-run lifecycle cleanup: safely prune stale temporary harness files
        pre_clean = clean_worktrees(vuln_id=vuln_id)
        if pre_clean["cleaned_count"] > 0:
            await broadcast(
                "log",
                f"[Lifecycle] Pre-run cleanup: Pruned {pre_clean['cleaned_count']} stale harness files ({pre_clean['bytes_freed']} bytes freed)."
            )

        await broadcast("log", f"[*] INITIATING AGENTWARD PRE-CONTEXT SHIELD: {target_file} (Provider: {ACTIVE_PROVIDER})")
        
        # Phase 1: Ingress
        await broadcast("phase_update", phase=1, status="Analyzing", color="border-yellow-600 bg-yellow-950/40", note="Prompt-Guard Scanning")
        s1 = await asyncio.to_thread(inspect_file_before_muse, target_file)
        p1_color = "border-emerald-600 bg-emerald-950/40" if s1["status"] == "ALLOW" else "border-amber-600 bg-amber-950/40"
        await broadcast("phase_update", phase=1, status=s1["status"], color=p1_color, note=s1.get("reason", "Clean")[:35])
        await broadcast("log", f"[Phase 1] Prompt Guard: {s1['status']} - Sanitized input generated.")

        # Phase 2: Sandbox Triage (bounded by MAX_PARALLEL_SANDBOXES)
        await broadcast("phase_update", phase=2, status="Sandboxing", color="border-yellow-600 bg-yellow-950/40", note="Docker Zero-Net + Syscall Audit")
        wt = create_isolated_worktree(vuln_id, target_file, s1["content"])
        triage = synthesize_verification_harness(target_file, s1["content"])
        async with sandbox_semaphore:
            test_res = await asyncio.to_thread(
                run_sandboxed, vuln_id, target_file, s1["content"], triage["verification_test_code"]
            )

        analysis = await triage_sandbox_result_async(test_res, target_file)
        confirmed = analysis["confirmed"]
        await broadcast(
            "syscall_trace",
            "\n".join(describe_syscall_trail(test_res.get("syscall_events", []))) or "<no syscalls recorded>",
            phase=2, status=analysis["verdict"],
            color="red" if confirmed else "emerald",
            note=(f"{analysis['event_count']} syscall events / backend={test_res.get('trace_backend', 'unknown')}"
                  f" / engine={test_res.get('engine', 'unknown')}"),
        )
        await broadcast(
            "analysis", json.dumps({k: analysis[k] for k in
                                    ("verdict", "evasion_score", "decisive_score", "weak_score", "signals")}),
            phase=2, status=analysis["verdict"], color="red" if confirmed else "emerald",
            note="decisive behavioural signal" if analysis["decisive_score"] else "no decisive signal",
        )

        p2_color = "border-red-600 bg-red-950/40" if confirmed else "border-emerald-600 bg-emerald-950/40"
        p2_status = "EXPLOITABLE" if confirmed else "BENIGN (FP)"
        await broadcast("phase_update", phase=2, status=p2_status, color=p2_color,
                        note="Reachable Sink Confirmed" if confirmed else "False Positive Dropped")
        await broadcast("log", f"[Phase 2] Sandbox verdict: {p2_status} "
                               f"(exit={analysis['exit_code']}, score={analysis['evasion_score']}, "
                               f"signals={'; '.join(analysis['signals']) or 'none'})")

        if not confirmed:
            await broadcast("log", "[*] Candidate finding is non-exploitable. Alert discarded.")
            return

        # Phase 3: Runtime Policy & Rewind Baseline
        await broadcast("phase_update", phase=3, status="Armed", color="border-blue-600 bg-blue-950/40", note="Rewind Checkpointed")
        test_file = os.path.join(wt, "verify_test.py")
        with open(test_file, "w") as f:
            f.write(triage["verification_test_code"])
        guard = AgentWardRuntimeGuard(wt)
        await broadcast("log", f"[Phase 3] Checkpoint SHA-256 manifest committed for {wt}")
        audit_check = await asyncio.to_thread(
            guard.audit_tool_call, "bash", f"pytest {test_file}"
        )
        audit_note = audit_check.get("message") or audit_check.get("violation") or "no message"
        p3_color = "border-emerald-600 bg-emerald-950/40" if audit_check["allowed"] else "border-red-600 bg-red-950/40"
        await broadcast("phase_update", phase=3,
                        status="ALLOWED" if audit_check["allowed"] else "BLOCKED",
                        color=p3_color, note=audit_note[:60])
        await broadcast("log", f"[Phase 3] Tool authorization hook: allowed={audit_check['allowed']} ({audit_note[:100]})")

        # Phase 4: Patching, Tripwire Synthesis & CodeShield
        await broadcast("phase_update", phase=4, status="Validating", color="border-yellow-600 bg-yellow-950/40", note="CodeShield + Tripwire Synthesis")
        s4 = await synthesize_and_gate_patch(target_file, simulate_insecure=False)
        p4_color = "border-emerald-600 bg-emerald-950/40" if s4["status"] == "ACCEPTED" else "border-red-600 bg-red-950/40"
        await broadcast("phase_update", phase=4, status=s4["status"], color=p4_color,
                        note=s4.get("tripwire_summary", "Purple Llama Review")[:60])
        await broadcast("log", f"[Phase 4] Patch verified through CodeShield: {s4['status']}")
        if s4.get("tripwire"):
            await broadcast("tripwire", json.dumps(s4["tripwire"]), phase=4,
                            status="ARMED" if s4["tripwire"]["has_logger"] else "DECOY",
                            color="violet", note=s4.get("tripwire_summary", "")[:80])

        if s4["status"] != "ACCEPTED":
            await broadcast("log", f"[!] Patch rejected. Issues: {s4['issues_found']}")
            return

        with open(s4["patch_path"]) as f:
            patched_code = f.read()

        # Phase 4.5: Adversarial Self-Play (mutate payload, replay against patch)
        await broadcast("phase_update", phase=4.5, status="Self-Playing", color="border-fuchsia-600 bg-fuchsia-950/40",
                        note="Mutating payload against patched sandbox")
        emit = make_emitter(default_phase=4.5, default_color="fuchsia")
        selfplay = await run_selfplay(
            target_file, patched_code, s1["content"],
            triage["sqli_payloads"], triage["cmd_payload"],
            on_event=emit,
        )
        sp_color = "border-emerald-600 bg-emerald-950/40" if selfplay["accepted"] else "border-red-600 bg-red-950/40"
        await broadcast("phase_update", phase=4.5,
                        status="PATCH ROBUST" if selfplay["accepted"] else "PATCH BYPASSED",
                        color=sp_color,
                        note=f"{len(selfplay['survived'])}/{len(selfplay['mutations'])} mutations survived")
        await broadcast("log", f"[Phase 4.5] Self-play {'accepted' if selfplay['accepted'] else 'rejected'} the patch "
                               f"({selfplay['source']} mutator, {len(selfplay['mutations'])} variants).")

        if not selfplay["accepted"]:
            await broadcast("log", "[!] Patch defeated by a polymorphic mutation. Regression skipped.")
            return

        # Phase 5: Regression Check (bounded by MAX_PARALLEL_SANDBOXES)
        await broadcast("phase_update", phase=5, status="Verifying", color="border-yellow-600 bg-yellow-950/40", note="Post-Patch Syscall Audit")
        async with sandbox_semaphore:
            post_res = await asyncio.to_thread(
                run_sandboxed, vuln_id, target_file, patched_code, triage["verification_test_code"]
            )
        post_analysis = await triage_sandbox_result_async(post_res, target_file)
        await broadcast(
            "syscall_trace",
            "\n".join(describe_syscall_trail(post_res.get("syscall_events", []))) or "<no syscalls recorded>",
            phase=5, status=post_analysis["verdict"],
            color="red" if post_analysis["confirmed"] else "emerald",
            note=f"{post_analysis['event_count']} syscall events (post-patch) / backend={post_res.get('trace_backend', 'unknown')}",
        )
        await broadcast(
            "analysis", json.dumps({k: post_analysis[k] for k in
                                    ("verdict", "evasion_score", "decisive_score", "weak_score", "signals")}),
            phase=5, status=post_analysis["verdict"], color="red" if post_analysis["confirmed"] else "emerald",
            note="regression trace analysed behaviourally",
        )
        remediated = not post_analysis["confirmed"] and s4.get("status") == "ACCEPTED"

        p5_status = "REMEDIATED" if remediated else "FAILED"
        p5_color = "border-emerald-600 bg-emerald-950/40" if remediated else "border-red-600 bg-red-950/40"
        p5_note = "PASSED • 0 CVEs Remaining" if remediated else "Vulnerability Still Active"
        await broadcast("phase_update", phase=5, status=p5_status, color=p5_color, note=p5_note)
        await broadcast("log", f"[Phase 5] Post-Patch verification: {'Vulnerability closed cleanly!' if remediated else 'Verification failed!'}"
                               f" (verdict={post_analysis['verdict']}, exit={post_analysis['exit_code']})")

        # Post-remediation lifecycle cleanup: prune temporary test harness files
        if remediated:
            post_clean = clean_worktrees(vuln_id=vuln_id)
            if post_clean["cleaned_count"] > 0:
                await broadcast(
                    "log",
                    f"[Phase 5] Workspace lifecycle: Pruned {post_clean['cleaned_count']} temporary harness files ({post_clean['bytes_freed']} bytes freed)."
                )

            # Phase 5.1: Semantic Variant Hunt across the surrounding corpus
            corpus_dir = os.path.dirname(target_file) or "."
            await broadcast("phase_update", phase=5.1, status="Hunting", color="border-violet-600 bg-violet-950/40",
                            note="Semantic variant sweep")
            hunt = await hunt_after_remediation(
                target_file, s1["content"], patched_code, corpus_dir,
                on_event=make_emitter(default_phase=5.1, default_color="violet"),
            )
            h_color = "border-emerald-600 bg-emerald-950/40" if not hunt["matches"] else "border-amber-600 bg-amber-950/40"
            await broadcast("phase_update", phase=5.1,
                            status="NO VARIANTS" if not hunt["matches"] else f"{len(hunt['matches'])} VARIANT(S)",
                            color=h_color, note=f"{hunt['scanned']} sibling files scanned")
            await broadcast("log", f"[Phase 5.1] Semantic hunt: {len(hunt['matches'])} variant(s) "
                                   f"across {hunt['scanned']} file(s) ({hunt['source']} scanner).")

        await broadcast("log", f"[+] PIPELINE RUN COMPLETE. Patch saved to: {s4['patch_path']}")
    except Exception as e:
        await broadcast("log", f"[!] Pipeline execution error: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.getenv("DASHBOARD_PORT", "8080")),
    )
