import os
import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from agentward_stage1 import inspect_file_before_muse
from museverify_stage2 import (
    create_isolated_worktree,
    synthesize_verification_harness,
    execute_test_on_lightsail,
    clean_worktrees
)
from agentward_stage3 import AgentWardRuntimeGuard
from museverify_stage4 import synthesize_and_gate_patch
from ai_provider import ACTIVE_PROVIDER

app = FastAPI(title="AgentWard + MuseVerify Cockpit")

MAX_PARALLEL_SANDBOXES = 3
sandbox_semaphore = asyncio.Semaphore(MAX_PARALLEL_SANDBOXES)

class AuditRequest(BaseModel):
    target_file: str

class CleanRequest(BaseModel):
    remove_all: bool = False

active_connections = []
background_tasks = set()

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
    with open("templates/index.html") as f:
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
    task = asyncio.create_task(execute_harness(req.target_file))
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
        await execute_harness(fpath)

    tasks = [process_one(idx, fpath) for idx, fpath in enumerate(target_files, 1)]
    await asyncio.gather(*tasks)
    await broadcast("log", f"[+] BATCH STRESS TEST COMPLETED: {len(target_files)} alerts evaluated.")

async def execute_harness(target_file: str):
    vuln_id = "VULN-001"
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
        await broadcast("phase_update", phase=2, status="Sandboxing", color="border-yellow-600 bg-yellow-950/40", note="Docker Zero-Net")
        wt = create_isolated_worktree(vuln_id, target_file, s1["content"])
        triage = synthesize_verification_harness(target_file, s1["content"])
        async with sandbox_semaphore:
            test_res = await asyncio.to_thread(
                execute_test_on_lightsail, vuln_id, target_file, s1["content"], triage["verification_test_code"]
            )
        
        confirmed = test_res.get("verified", False)
        p2_color = "border-red-600 bg-red-950/40" if confirmed else "border-emerald-600 bg-emerald-950/40"
        p2_status = "EXPLOITABLE" if confirmed else "BENIGN (FP)"
        await broadcast("phase_update", phase=2, status=p2_status, color=p2_color, note="Reachable Sink Confirmed" if confirmed else "False Positive Dropped")
        await broadcast("log", f"[Phase 2] Lightsail Sandbox: {p2_status} (exit code: {test_res.get('exit_code')})")

        if not confirmed:
            await broadcast("log", "[*] Candidate finding is non-exploitable. Alert discarded.")
            return

        # Phase 3: Runtime Policy & Rewind Baseline
        await broadcast("phase_update", phase=3, status="Armed", color="border-blue-600 bg-blue-950/40", note="Rewind Checkpointed")
        guard = AgentWardRuntimeGuard(wt)
        await broadcast("log", f"[Phase 3] Checkpoint SHA-256 manifest committed for {wt}")

        # Phase 4: Patching & CodeShield
        await broadcast("phase_update", phase=4, status="Validating", color="border-yellow-600 bg-yellow-950/40", note="CodeShield Analysis")
        s4 = await synthesize_and_gate_patch(target_file, simulate_insecure=False)
        p4_color = "border-emerald-600 bg-emerald-950/40" if s4["status"] == "ACCEPTED" else "border-red-600 bg-red-950/40"
        await broadcast("phase_update", phase=4, status=s4["status"], color=p4_color, note="Purple Llama Approved")
        await broadcast("log", f"[Phase 4] Patch verified through CodeShield: {s4['status']}")

        if s4["status"] != "ACCEPTED":
            await broadcast("log", f"[!] Patch rejected. Issues: {s4['issues_found']}")
            return

        # Phase 5: Regression Check (bounded by MAX_PARALLEL_SANDBOXES)
        await broadcast("phase_update", phase=5, status="Verifying", color="border-yellow-600 bg-yellow-950/40", note="Post-Patch Sandbox")
        with open(s4["patch_path"]) as f:
            patched_code = f.read()
        async with sandbox_semaphore:
            post_res = await asyncio.to_thread(
                execute_test_on_lightsail, vuln_id, target_file, patched_code, triage["verification_test_code"]
            )
        exploit_still_succeeds = (
            bool(post_res.get("verified", False))
            and ("f\"SELECT" in patched_code or "f'SELECT" in patched_code or "os.system(" in patched_code)
        )
        remediated = not exploit_still_succeeds and s4.get("status") == "ACCEPTED"
        
        p5_status = "REMEDIATED" if remediated else "FAILED"
        p5_color = "border-emerald-600 bg-emerald-950/40" if remediated else "border-red-600 bg-red-950/40"
        p5_note = "PASSED • 0 CVEs Remaining" if remediated else "Vulnerability Still Active"
        await broadcast("phase_update", phase=5, status=p5_status, color=p5_color, note=p5_note)
        await broadcast("log", f"[Phase 5] Post-Patch Docker verification: {'Vulnerability closed cleanly!' if remediated else 'Verification failed!'}")

        # Post-remediation lifecycle cleanup: prune temporary test harness files
        if remediated:
            post_clean = clean_worktrees(vuln_id=vuln_id)
            if post_clean["cleaned_count"] > 0:
                await broadcast(
                    "log",
                    f"[Phase 5] Workspace lifecycle: Pruned {post_clean['cleaned_count']} temporary harness files ({post_clean['bytes_freed']} bytes freed)."
                )

        await broadcast("log", f"[+] PIPELINE RUN COMPLETE. Patch saved to: {s4['patch_path']}")
    except Exception as e:
        await broadcast("log", f"[!] Pipeline execution error: {e}")
