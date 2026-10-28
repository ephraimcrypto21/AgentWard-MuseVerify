#!/usr/bin/env python3
"""
MuseVerify Remote Sandbox Node (Stages 2 & 5).

Runs an untrusted verification harness inside a zero-network Docker container and
returns BOTH the process output and a structured syscall audit trail, so the
AI auditor can reason about *behaviour* (execve/openat/connect) instead of
trusting an exit code that a polymorphic payload can trivially forge.

Telemetry backends, in preference order:
  1. `strace -f` from inside the container (needs SYS_PTRACE, traced with
     --cap-add; auto-skipped when the image has no strace binary).
  2. A `sys.addaudithook` shim injected next to the harness. It always runs and
     emits the same normalized event schema, so a missing strace never leaves
     the auditor blind.

Exposed endpoints:
  GET  /                -> health
  POST /execute         -> run harness + syscall trace
  POST /run-sandbox-test-> alias kept for older clients
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="MuseVerify Sandbox Node (Stage 2/5)")

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.12-slim")
SANDBOX_TIMEOUT_S = int(os.environ.get("SANDBOX_TIMEOUT_S", "15"))
MAX_EVENTS = 500
TRACE_SYSCALLS = "execve,execveat,openat,open,connect,unlinkat"

# Audit events we translate into syscall-shaped records.
_TRACED_AUDIT_EVENTS = {
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "open",
    "os.remove",
    "os.unlink",
    "socket.connect",
    "socket.getaddrinfo",
}

# Paths that produce noise on every single Python start.
_NOISE_FRAGMENTS = (
    "site-packages",
    "__pycache__",
    "/usr/lib/python",
    "/usr/local/lib/python",
    ".so",
    ".pyc",
)

RUNNER_SHIM = r'''
import json, os, sys, runpy

LOG_PATH = os.environ.get("AGENTWARD_AUDIT_LOG", "syscall_audit.jsonl")
TRACED = %(traced)s
NOISE = %(noise)s
MAX = %(max_events)d
_state = {"n": 0, "depth": 0}
_handle = open(LOG_PATH, "w", encoding="utf-8")


def _emit(kind, detail):
    if _state["n"] >= MAX:
        return
    _state["n"] += 1
    _handle.write(json.dumps({"syscall": kind, **detail}) + "\n")
    _handle.flush()


def _noisy(path):
    return any(frag in path for frag in NOISE)


def _hook(event, args):
    if event not in TRACED:
        return
    if event in ("subprocess.Popen", "os.exec", "os.posix_spawn"):
        exe = args[0] if args else "?"
        argv = args[1] if len(args) > 1 else []
        if isinstance(argv, (list, tuple)):
            argv = [str(a) for a in argv]
        _emit("sys_enter_execve", {"argv": str(exe), "args": str(argv)[:400], "source": event})
    elif event == "os.system":
        _emit("sys_enter_execve", {"argv": "/bin/sh", "args": str(args[0])[:400], "source": event})
    elif event == "open":
        path = str(args[0]) if args else "?"
        if _noisy(path):
            return
        mode = args[1] if len(args) > 1 else "r"
        _emit("sys_enter_openat", {"path": path, "flag": str(mode), "source": event})
    elif event in ("os.remove", "os.unlink"):
        _emit("sys_enter_unlinkat", {"path": str(args[0]) if args else "?", "source": event})
    elif event == "socket.connect":
        _emit("sys_enter_connect", {"addr": str(args[1]) if len(args) > 1 else "?", "source": event})
    elif event == "socket.getaddrinfo":
        _emit("sys_enter_connect", {"addr": f"dns:{args[0]}" if args else "?", "source": event})


sys.addaudithook(_hook)
script = sys.argv[1] if len(sys.argv) > 1 else "verify_test.py"
sys.argv = [script]
try:
    runpy.run_path(script, run_name="__main__")
finally:
    _handle.close()
'''

WRAPPER_SH = """#!/bin/sh
# Prefer kernel-level tracing; fall back to the in-process audit hook shim.
if command -v strace >/dev/null 2>&1; then
  exec strace -f -qq -e trace=%(syscalls)s \\
       -o /workspace/syscall_audit.strace \\
       python3 /workspace/agentward_runner.py /workspace/verify_test.py
fi
exec python3 /workspace/agentward_runner.py /workspace/verify_test.py
"""


class SandboxRequest(BaseModel):
    vuln_id: str = "VULN-001"
    target_file: str = ""
    target_filename: str = ""
    code_content: str = ""
    sanitized_target_code: str = ""
    test_code: str = ""
    test_script: str = ""
    poc_script: str = ""
    capture_mode: str = "auto"


def _flag_set(raw):
    parts = [p.strip() for p in str(raw or "").replace(",", " ").split() if p.strip()]
    return set(parts)


def _split_args(raw: str) -> list:
    """Split an strace argument list on top-level commas, respecting quotes."""
    args, buf, quote, depth = [], [], None, 0
    for char in raw:
        if quote:
            if char == quote:
                quote = None
            buf.append(char)
        elif char in ('"', "'"):
            quote = char
            buf.append(char)
        elif char in "([{":
            depth += 1
            buf.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            buf.append(char)
        elif char == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(char)
    if buf:
        args.append("".join(buf).strip())
    return args


def _unquote(token: str) -> str:
    return token.strip().strip('"').strip("'")


def normalize_strace(text: str) -> list:
    """Convert raw strace lines into the same schema the audit shim emits.

    `openat`/`execveat`/`connect` carry a leading dirfd or fd, so the payload
    lives in the second argument — parsing positionally keeps paths and remote
    addresses intact.
    """
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("+++", "---", "exit", "strace:")):
            continue
        name, _, rest = line.partition("(")
        name = name.split()[-1] if name else ""
        rest = rest.split(" = ")[0]
        if rest.endswith(")"):
            rest = rest[:-1]
        args = _split_args(rest)
        if name in ("execve", "execveat"):
            argv = _unquote(args[1] if name == "execveat" and len(args) > 1 else (args[0] if args else ""))
            if not argv or _is_noisy(argv):
                continue
            events.append({"syscall": "sys_enter_execve", "argv": argv[:400],
                           "args": rest[:400],
                           "shell": os.path.basename(argv) in ("sh", "bash", "dash"),
                           "source": "strace"})
        elif name in ("openat", "open"):
            path = _unquote(args[1]) if name == "openat" and len(args) > 1 else (
                _unquote(args[0]) if args else "")
            if not path or _is_noisy(path):
                continue
            flag = args[2] if name == "openat" and len(args) > 2 else (
                args[1] if len(args) > 1 else "?")
            events.append({"syscall": "sys_enter_openat", "path": path[:300],
                           "flag": flag[:60], "source": "strace"})
        elif name == "connect":
            addr = args[1] if len(args) > 1 else (args[0] if args else "")
            events.append({"syscall": "sys_enter_connect", "addr": addr[:200], "source": "strace"})
        elif name in ("unlink", "unlinkat"):
            path = _unquote(args[1]) if name == "unlinkat" and len(args) > 1 else (
                _unquote(args[0]) if args else "")
            events.append({"syscall": "sys_enter_unlinkat", "path": path[:300], "source": "strace"})
        if len(events) >= MAX_EVENTS:
            break
    return events


def _is_noisy(path: str) -> bool:
    return any(frag in path for frag in _NOISE_FRAGMENTS)


def _audit_events(path: str) -> list:
    events = []
    if not os.path.exists(path):
        return events
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and "syscall" in record:
                events.append(record)
            if len(events) >= MAX_EVENTS:
                break
    return events


def _write_harness_files(sandbox_dir: str, req: SandboxRequest) -> str:
    target_name = os.path.basename(req.target_file or req.target_filename or "target.py")
    with open(os.path.join(sandbox_dir, target_name), "w") as handle:
        handle.write(req.code_content or req.sanitized_target_code)
    with open(os.path.join(sandbox_dir, "verify_test.py"), "w") as handle:
        handle.write(req.test_code or req.test_script or req.poc_script)
    with open(os.path.join(sandbox_dir, "agentward_runner.py"), "w") as handle:
        handle.write(RUNNER_SHIM % {
            "traced": json.dumps(sorted(_TRACED_AUDIT_EVENTS)),
            "noise": json.dumps(list(_NOISE_FRAGMENTS)),
            "max_events": MAX_EVENTS,
        })
    wrapper = os.path.join(sandbox_dir, "run.sh")
    with open(wrapper, "w") as handle:
        handle.write(WRAPPER_SH % {"syscalls": TRACE_SYSCALLS})
    os.chmod(wrapper, 0o755)
    return target_name


def _run_container(sandbox_dir: str):
    use_trace = os.environ.get("SANDBOX_STRACE", "1") != "0"
    base = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", "256m",
        "--cpus", "0.5",
        "-v", f"{sandbox_dir}:/workspace:rw",
        "-w", "/workspace",
        "--env", "AGENTWARD_AUDIT_LOG=/workspace/syscall_audit.jsonl",
        "--env", "PYTHONUNBUFFERED=1",
    ]
    if use_trace:
        base += ["--cap-add", "SYS_PTRACE"]
    return subprocess.run(
        base + [SANDBOX_IMAGE, "/bin/sh", "/workspace/run.sh"],
        capture_output=True, text=True, timeout=SANDBOX_TIMEOUT_S,
    )


def _run_local(sandbox_dir: str):
    env = dict(os.environ, AGENTWARD_AUDIT_LOG=os.path.join(sandbox_dir, "syscall_audit.jsonl"))
    return subprocess.run(
        ["python3", "agentward_runner.py", "verify_test.py"],
        cwd=sandbox_dir, capture_output=True, text=True, timeout=10, env=env,
    )


@app.get("/")
@app.get("/health")
def health():
    have_docker = shutil.which("docker") is not None
    return {
        "status": "ok",
        "service": "MuseVerify Sandbox Node",
        "docker": have_docker,
        "syscall_telemetry": "strace+audit-hook (auto fallback)",
    }


@app.post("/execute")
@app.post("/run-sandbox-test")
@app.post("/run-poc-sandbox")
def execute(req: SandboxRequest):
    sandbox_dir = tempfile.mkdtemp(prefix=f"museverify_{req.vuln_id}_")
    engine = "docker"
    try:
        _write_harness_files(sandbox_dir, req)
        try:
            proc = _run_container(sandbox_dir)
            if proc.returncode != 0 and (
                "permission denied" in proc.stderr.lower()
                or "cannot connect" in proc.stderr.lower()
                or "cannot connect to the docker daemon" in proc.stderr.lower()
            ):
                raise RuntimeError("docker unavailable")
        except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError):
            engine = "local"
            proc = _run_local(sandbox_dir)

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        verified = proc.returncode == 0 and ("VULN_CONFIRMED" in stdout or "EXPLOIT_VERIFIED" in stdout)

        strace_path = os.path.join(sandbox_dir, "syscall_audit.strace")
        events = normalize_strace(open(strace_path, encoding="utf-8", errors="replace").read()) \
            if os.path.exists(strace_path) else []
        events += _audit_events(os.path.join(sandbox_dir, "syscall_audit.jsonl"))

        # Deduplicate but preserve ordering of first observation.
        seen, uniq = set(), []
        for event in events:
            key = (event.get("syscall"), event.get("argv") or event.get("path") or event.get("addr"))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(event)

        return {
            "vuln_id": req.vuln_id,
            "verified": verified,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "engine": engine,
            "trace_backend": "strace" if any(e.get("source") == "strace" for e in uniq) else "audit_hook",
            "syscall_events": uniq[:MAX_EVENTS],
        }
    except subprocess.TimeoutExpired:
        return {"vuln_id": req.vuln_id, "verified": False, "exit_code": -1, "stdout": "",
                "stderr": "Sandbox timed out", "engine": engine,
                "trace_backend": "none", "syscall_events": []}
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
